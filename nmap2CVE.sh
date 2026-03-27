#!/bin/bash
# Escanea un XML de nmap y consulta CVEs en NVD por cada servicio encontrado
# Uso: ./nmap2CVE.sh archivo.xml

[ -z "$1" ] && { echo "Uso: $0 archivo.xml"; exit 1; }
[ ! -f "$1" ] && { echo "Error: archivo '$1' no encontrado"; exit 1; }

XML="$1"
MAX_THREADS=10
NVD_DELAY="0.6"
NVD_RETRIES=3
WORK_DIR=$(mktemp -d)
CACHE_DIR="$WORK_DIR/cache"
mkdir -p "$CACHE_DIR"
trap 'rm -rf "$WORK_DIR"' EXIT

# Colores
R=$'\e[31m' Y=$'\e[33m' G=$'\e[32m' B=$'\e[34m' C=$'\e[36m' N=$'\e[0m'
export R Y G B C N CACHE_DIR NVD_DELAY NVD_RETRIES

# Formato: IP|HOSTNAME|PUERTO|SERVICIO|PRODUCTO|VERSION|CPE
ENTRADAS=$(xmlstarlet sel -t \
    -m "//host/ports/port/service[@version]" \
    -v "concat(ancestor::host/address/@addr,'|',\
               ancestor::host/hostnames/hostname/@name,'|',\
               ../@portid,'|',@name,'|',@product,'|',@version,'|',\
               cpe)" -n \
    "$XML" | tr -d '\r' | sort -u)

[ -z "$ENTRADAS" ] && { echo "No se encontraron servicios con versión en el XML"; exit 1; }

# ── Convierte CPE 2.2 → 2.3 ──────────────────────────────────────────────────
cpe22_a_23() {
    local cpe22
    cpe22=$(echo "$1" | tr -d '[:space:]')
    local tipo_letra vendor prod ver
    tipo_letra=$(echo "$cpe22" | grep -oP '(?<=cpe:/)[aoh]')
    vendor=$(echo "$cpe22" | cut -d':' -f3)
    prod=$(echo "$cpe22"   | cut -d':' -f4)
    ver=$(echo "$cpe22"    | cut -d':' -f5)
    [ -z "$ver" ] && ver="*"
    echo "cpe:2.3:${tipo_letra}:${vendor}:${prod}:${ver}:*:*:*:*:*:*:*"
}

# ── Expande nombres cortos al nombre completo que usa NVD ─────────────────────
expandir_producto() {
    local p="$1"
    p=$(echo "$p" | sed -E \
        -e 's/Microsoft IIS/Microsoft Internet Information Services/gI' \
        -e 's/Microsoft HTTPAPI/Microsoft HTTP API/gI' \
        -e 's/\b(httpd|server|service|daemon)\b//gI')
    echo "$p" | tr -s ' ' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

# ── Llama a NVD con reintentos backoff, guarda en caché ──────────────────────
nvd_fetch() {
    local param_type="$1" param_val="$2"
    local cache_file="$CACHE_DIR/$(echo "${param_type}_${param_val}" | md5sum | cut -d' ' -f1).json"
    # Caché válido: fichero existe y tiene la clave vulnerabilities (aunque sea array vacío)
    if [ -f "$cache_file" ] && jq -e 'has("vulnerabilities")' "$cache_file" &>/dev/null; then
        return 0
    fi

    local url intento=1 resp
    [ "$param_type" = "cpe" ] \
        && url="https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=${param_val}" \
        || url="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${param_val}"

    while [ "$intento" -le "$NVD_RETRIES" ]; do
        sleep "$NVD_DELAY"
        resp=$(curl -sf --max-time 15 "$url")
        local curl_exit=$?
        if echo "$resp" | jq -e '.vulnerabilities' &>/dev/null; then
            echo "$resp" > "$cache_file"
            return 0
        fi
        # Muestra el error para diagnóstico
        local http_status=$(echo "$resp" | jq -r '.status // empty' 2>/dev/null)
        [ -n "$http_status" ] && printf "\r${Y}  [intento %d] HTTP %s: %s${N}\n" "$intento" "$http_status" "$(echo "$resp" | jq -r '.message // empty' 2>/dev/null)" >&2
        [ "$curl_exit" -ne 0 ] && printf "\r${Y}  [intento %d] curl error %d${N}\n" "$intento" "$curl_exit" >&2
        sleep $(( 2 ** intento ))
        (( intento++ ))
    done
    return 1
}

# ─────────────────────────────────────────────────────────────────────────────
# FASE 1: Poblar caché secuencialmente — sin rate limiting
# ─────────────────────────────────────────────────────────────────────────────
echo -e "${B}Consultando NVD API...${N}"
declare -A QUERY_VISTO
declare -i ACTUAL=0

while IFS='|' read -r _ _ _ _ producto version cpe; do
    [ -z "$producto" ] && continue
    cpe=$(echo "$cpe" | tr -d '[:space:]')

    version_limpia=$(echo "$version" | grep -oP '^\S+')
    version_fallback=$(echo "$version_limpia" | grep -oP '^\d+\.\d+')
    producto_nvd=$(expandir_producto "$producto")

    if echo "$cpe" | grep -qP 'cpe:/.:\w+:\w+:\d'; then
        cpe23=$(cpe22_a_23 "$cpe")
        key="cpe_${cpe23}"
        if [ -z "${QUERY_VISTO[$key]}" ]; then
            QUERY_VISTO[$key]=1
            (( ACTUAL++ ))
            printf "\r${B}[%d]${N} %s %-50s" "$ACTUAL" "CPE    " "${cpe23:0:55}" >&2
            nvd_fetch "cpe" "$cpe23"
            # Fallback a keyword si CPE devuelve 0 (CVEs con rangos de versión)
            cache_cpe="$CACHE_DIR/$(echo "cpe_${cpe23}" | md5sum | cut -d' ' -f1).json"
            if [ -f "$cache_cpe" ] && [ "$(jq '.vulnerabilities | length' "$cache_cpe")" -eq 0 ]; then
                for ver in "$version_limpia" "$version_fallback"; do
                    [ -z "$ver" ] && continue
                    query=$(printf '%s %s' "$producto_nvd" "$ver" | tr ' ' '+')
                    key2="keyword_${query}"
                    if [ -z "${QUERY_VISTO[$key2]}" ]; then
                        QUERY_VISTO[$key2]=1
                        (( ACTUAL++ )) || true
                        printf "\r${B}[%d]${N} %s %-50s" "$ACTUAL" "keyword" "${query:0:55}" >&2
                        nvd_fetch "keyword" "$query"
                    fi
                done
            fi
        fi
    else
        for ver in "$version_limpia" "$version_fallback"; do
            [ -z "$ver" ] && continue
            query=$(printf '%s %s' "$producto_nvd" "$ver" | tr ' ' '+')
            key="keyword_${query}"
            if [ -z "${QUERY_VISTO[$key]}" ]; then
                QUERY_VISTO[$key]=1
                (( ACTUAL++ ))
                printf "\r${B}[%d]${N} %s %-50s" "$ACTUAL" "keyword" "${query:0:55}" >&2
                nvd_fetch "keyword" "$query"
            fi
        done
    fi
done < <(echo "$ENTRADAS")
echo -e "\r${G}✓ Consultas completadas${N}$(printf '%40s' '')" >&2

# ─────────────────────────────────────────────────────────────────────────────
# FASE 2: Procesar en paralelo — solo lectura de caché
# ─────────────────────────────────────────────────────────────────────────────
procesar_servicio() {
    local ip="$1" hostname="$2" puerto="$3" servicio="$4" producto="$5" version="$6" cpe="$7" outfile="$8"
    local url cache_file resp num max_cvss color
    local version_limpia version_fallback producto_nvd

    cpe=$(echo "$cpe" | tr -d '[:space:]')
    version_limpia=$(echo "$version" | grep -oP '^\S+')
    version_fallback=$(echo "$version_limpia" | grep -oP '^\d+\.\d+')
    producto_nvd=$(expandir_producto "$producto")

    if echo "$cpe" | grep -qP 'cpe:/.:\w+:\w+:\d'; then
        local cpe23
        cpe23=$(cpe22_a_23 "$cpe")
        cache_file="$CACHE_DIR/$(echo "cpe_${cpe23}" | md5sum | cut -d' ' -f1).json"
        url="https://nvd.nist.gov/vuln/search#/nvd/home?cpeFilterMode=cpe&cpeName=${cpe23}&resultType=records"

        # Fallback a keyword si CPE devuelve 0 (CVEs con rangos de versión)
        if [ -f "$cache_file" ] && [ "$(jq '.vulnerabilities | length' "$cache_file" 2>/dev/null)" -eq 0 ]; then
            local query_fb
            query_fb=$(printf '%s %s' "$producto_nvd" "$version_limpia" | tr ' ' '+')
            local cache_kw="$CACHE_DIR/$(echo "keyword_${query_fb}" | md5sum | cut -d' ' -f1).json"
            if [ -f "$cache_kw" ] && [ "$(jq '.vulnerabilities | length' "$cache_kw" 2>/dev/null)" -gt 0 ]; then
                cache_file="$cache_kw"
                url="https://nvd.nist.gov/vuln/search#/nvd/home?cpeFilterMode=cpe&cpeName=${cpe23}&resultType=records"
            fi
        fi
    else
        local query
        query=$(printf '%s %s' "$producto_nvd" "$version_limpia" | tr ' ' '+')
        cache_file="$CACHE_DIR/$(echo "keyword_${query}" | md5sum | cut -d' ' -f1).json"

        # Fallback a versión reducida si 0 resultados
        if { [ ! -f "$cache_file" ] || [ "$(jq '.vulnerabilities | length' "$cache_file" 2>/dev/null)" -eq 0 ]; } \
            && [ -n "$version_fallback" ] && [ "$version_fallback" != "$version_limpia" ]; then
            local query_fb
            query_fb=$(printf '%s %s' "$producto_nvd" "$version_fallback" | tr ' ' '+')
            local cache_fb="$CACHE_DIR/$(echo "keyword_${query_fb}" | md5sum | cut -d' ' -f1).json"
            [ -f "$cache_fb" ] && cache_file="$cache_fb" && query="$query_fb"
        fi

        url="https://nvd.nist.gov/vuln/search#/nvd/home?keyword=$(printf '%s' "${query//+/ }" | jq -sRr @uri)&resultType=records"
    fi

    if [ ! -f "$cache_file" ]; then
        {
            echo "-1"
            echo -e "  - $puerto $servicio $producto $version"
            echo -e "      ${Y}Error consultando NVD API${N}"
            echo -e "      ${C}$url${N}"
        } > "$outfile"
        return
    fi

    resp=$(cat "$cache_file")
    num=$(echo "$resp" | jq '.vulnerabilities | length')
    max_cvss=$(echo "$resp" | jq '
        [ .vulnerabilities[].cve.metrics |
          (.cvssMetricV31[]?.cvssData.baseScore //
           .cvssMetricV2[]?.cvssData.baseScore  //
           empty)
        ] | max // 0')

    if   awk "BEGIN {exit !($max_cvss >= 7)}"; then color=$R
    elif [ "$num" -gt 0 ];                     then color=$Y
    else                                             color=$G
    fi

    {
        echo "$max_cvss"
        echo -e "  - $puerto $servicio $producto $version"
        [ "$num" -eq 0 ] \
            && echo -e "      ${G}0 CVEs${N}" \
            || echo -e "      ${color}${num} CVEs — CVSS max: ${max_cvss}${N}"
        echo -e "      ${C}$url${N}"
    } > "$outfile"
}
export -f procesar_servicio expandir_producto cpe22_a_23 nvd_fetch

while IFS='|' read -r ip hostname puerto servicio producto version cpe; do
    [ -z "$puerto" ] && continue
    mkdir -p "$WORK_DIR/$ip"
    outfile="$WORK_DIR/$ip/${puerto}.txt"

    until [ "$(jobs -r | wc -l)" -lt "$MAX_THREADS" ]; do sleep 0.1; done
    procesar_servicio "$ip" "$hostname" "$puerto" "$servicio" "$producto" "$version" "$cpe" "$outfile" &

done < <(echo "$ENTRADAS")

wait

# ── Imprime IPs ordenadas por CVSS máximo desc ────────────────────────────────
while IFS='|' read -r ip hostname _; do echo "$ip|$hostname"; done < <(echo "$ENTRADAS") \
| sort -u \
| while IFS='|' read -r ip hostname; do
    ip_score=$(for f in "$WORK_DIR/$ip/"*.txt; do
        [ -f "$f" ] && head -1 "$f"
    done | sort -rg | head -1)
    printf '%s|%s|%s\n' "${ip_score:-0}" "$ip" "${hostname:-$ip}"
done \
| sort -rg \
| while IFS='|' read -r _ ip label; do
    echo -e "${B}${label}${N}"

    for f in "$WORK_DIR/$ip/"*.txt; do
        [ -f "$f" ] && printf '%s %s\n' "$(head -1 "$f")" "$f"
    done \
    | sort -rg \
    | awk '{print $2}' \
    | xargs -I{} tail -n +2 {}

    echo
done
