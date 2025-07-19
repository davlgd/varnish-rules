#!/bin/bash
# generate_varnish_security.sh - Génère la configuration VCL de sécurité

# Configuration
VCL_FILE="${VCL_FILE:-clevercloud/varnish.vcl}"
RATE_LIMIT="${RATE_LIMIT:-100}"  # requêtes par minute

# IPs à bloquer (modifiez cette liste selon vos besoins)
BLOCKED_IPS=(
  "1.2.3.4"
)

# Récupérer les reverse proxies de confiance
get_trusted_proxies() {
    echo "${CC_REVERSE_PROXY_IPS:-}" | tr ',' '\n' | sed 's/^[ \t]*//;s/[ \t]*$//' | grep -v '^$'
}

# Créer le répertoire si nécessaire
mkdir -p "$(dirname "$VCL_FILE")"

# Générer la configuration VCL avec vsthrottle
cat > "$VCL_FILE" << 'EOF'
import std;
import vsthrottle;

sub vcl_recv {
    # Extraction de l'IP réelle du client
EOF

# Gestion des reverse proxies de confiance
TRUSTED_PROXIES=$(get_trusted_proxies)
if [ -n "$TRUSTED_PROXIES" ]; then
    echo "    # Faire confiance aux reverse proxies configurés" >> "$VCL_FILE"
    echo "    if (" >> "$VCL_FILE"
    
    FIRST=true
    while IFS= read -r proxy_ip; do
        [ -z "$proxy_ip" ] && continue
        if [ "$FIRST" = true ]; then
            echo "        client.ip == \"$proxy_ip\"" >> "$VCL_FILE"
            FIRST=false
        else
            echo "        || client.ip == \"$proxy_ip\"" >> "$VCL_FILE"
        fi
    done <<< "$TRUSTED_PROXIES"
    
    cat >> "$VCL_FILE" << 'EOF'
        ) {
        if (req.http.X-Forwarded-For) {
            set req.http.X-Real-IP = regsub(req.http.X-Forwarded-For, ",.*$", "");
        } else {
            set req.http.X-Real-IP = client.ip;
        }
    } else {
        set req.http.X-Real-IP = client.ip;
    }
EOF
else
    echo "    set req.http.X-Real-IP = client.ip;" >> "$VCL_FILE"
fi

# Blocage des IPs
if [ ${#BLOCKED_IPS[@]} -gt 0 ]; then
    echo "" >> "$VCL_FILE"
    echo "    # Blocage d'IPs spécifiques" >> "$VCL_FILE"
    echo "    if (" >> "$VCL_FILE"
    
    for i in "${!BLOCKED_IPS[@]}"; do
        if [ $i -eq 0 ]; then
            echo "        req.http.X-Real-IP == \"${BLOCKED_IPS[$i]}\"" >> "$VCL_FILE"
        else
            echo "        || req.http.X-Real-IP == \"${BLOCKED_IPS[$i]}\"" >> "$VCL_FILE"
        fi
    done
    
    cat >> "$VCL_FILE" << 'EOF'
        ) {
        std.log("IP bloquée: " + req.http.X-Real-IP);
        return (synth(403, "Access denied"));
    }
EOF
fi

# Rate limiting avec vsthrottle - écrire ligne par ligne pour éviter les problèmes heredoc
echo "" >> "$VCL_FILE"
echo "    # Rate limiting avec vsthrottle ($RATE_LIMIT requêtes par minute par IP)" >> "$VCL_FILE"
echo "    if (vsthrottle.is_denied(req.http.X-Real-IP, $RATE_LIMIT, 60s)) {" >> "$VCL_FILE"
echo "        std.log(\"Rate limit dépassé: \" + req.http.X-Real-IP + \" (max $RATE_LIMIT/min)\");" >> "$VCL_FILE"
echo "        return (synth(429, \"Rate limit exceeded\"));" >> "$VCL_FILE"
echo "    }" >> "$VCL_FILE"
echo "" >> "$VCL_FILE"
echo "    # Stocker le quota restant pour l'ajouter dans la réponse" >> "$VCL_FILE"
echo "    set req.http.X-Rate-Remaining = vsthrottle.remaining(req.http.X-Real-IP, $RATE_LIMIT, 60s);" >> "$VCL_FILE"
echo "" >> "$VCL_FILE"
echo "    return (pass);" >> "$VCL_FILE"
echo "}" >> "$VCL_FILE"

# Fonctions de gestion des erreurs et réponses
echo "" >> "$VCL_FILE"
echo "sub vcl_synth {" >> "$VCL_FILE"
echo "    if (resp.status == 403) {" >> "$VCL_FILE"
echo "        set resp.http.Content-Type = \"text/plain\";" >> "$VCL_FILE"
echo "        set resp.body = \"Access denied\";" >> "$VCL_FILE"
echo "        return (deliver);" >> "$VCL_FILE"
echo "    }" >> "$VCL_FILE"
echo "" >> "$VCL_FILE"
echo "    if (resp.status == 429) {" >> "$VCL_FILE"
echo "        set resp.http.Content-Type = \"text/plain\";" >> "$VCL_FILE"
echo "        set resp.http.Retry-After = \"60\";" >> "$VCL_FILE"
echo "        set resp.http.X-RateLimit-Limit = \"$RATE_LIMIT\";" >> "$VCL_FILE"
echo "        set resp.http.X-RateLimit-Remaining = \"0\";" >> "$VCL_FILE"
echo "        set resp.http.X-RateLimit-Reset = \"60\";" >> "$VCL_FILE"
echo "        set resp.body = \"Rate limit exceeded\";" >> "$VCL_FILE"
echo "        return (deliver);" >> "$VCL_FILE"
echo "    }" >> "$VCL_FILE"
echo "}" >> "$VCL_FILE"

# Fonction de livraison avec headers
echo "" >> "$VCL_FILE"
echo "sub vcl_deliver {" >> "$VCL_FILE"
echo "    # Headers informatifs sur l'IP" >> "$VCL_FILE"
echo "    set resp.http.X-Client-IP = req.http.X-Real-IP;" >> "$VCL_FILE"
echo "" >> "$VCL_FILE"
echo "    # Headers de rate limiting" >> "$VCL_FILE"
echo "    set resp.http.X-RateLimit-Limit = \"$RATE_LIMIT\";" >> "$VCL_FILE"
echo "    set resp.http.X-RateLimit-Remaining = req.http.X-Rate-Remaining;" >> "$VCL_FILE"
echo "    set resp.http.X-RateLimit-Reset = \"60\";" >> "$VCL_FILE"
echo "" >> "$VCL_FILE"
echo "    # Nettoyer les headers internes" >> "$VCL_FILE"
echo "    unset resp.http.X-Real-IP;" >> "$VCL_FILE"
echo "    unset resp.http.X-Rate-Remaining;" >> "$VCL_FILE"
echo "}" >> "$VCL_FILE"

echo "Configuration VCL générée: $VCL_FILE"
echo "✓ Blocage d'IPs: ${#BLOCKED_IPS[@]} IPs"
if [ -n "$TRUSTED_PROXIES" ]; then
    echo "✓ Reverse proxies de confiance: $(echo "$TRUSTED_PROXIES" | wc -l) IPs"
fi
echo "✓ Rate limiting: $RATE_LIMIT requêtes/minute par IP (vsthrottle)"
echo "✓ Headers de quota: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset"

