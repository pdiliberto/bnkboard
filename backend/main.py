from fastapi import FastAPI
from fastapi.responses import JSONResponse
import subprocess, yaml

app = FastAPI()

def run_kubectl(cmd):
    try:
        output = subprocess.check_output(cmd, text=True)
        return yaml.safe_load(output)
    except subprocess.CalledProcessError:
        return None

# --- NUOVA API: elenco Gateway con listener e route ---
@app.get("/api/gateways")
def list_gateways():
    try:
        # Recupera tutti i gateway in una singola chiamata
        gw_data = run_kubectl(["kubectl", "get", "gateway.gateway.networking.k8s.io", "-A", "-o", "json"])
        if not gw_data:
            return {"gateways": []}

        # Recupera tutte le L4Route e HTTPRoute globali
        l4_data = run_kubectl(["kubectl", "get", "l4route.gateway.k8s.f5net.com", "-A", "-o", "json"]) or {}
        http_data = run_kubectl(["kubectl", "get", "httproute.gateway.networking.k8s.io", "-A", "-o", "json"]) or {}

        gateways_result = []

        for gw in gw_data.get("items", []):
            gw_name = gw["metadata"]["name"]
            ns = gw["metadata"]["namespace"]
            # Gestione sicura dell'IP
            addresses = gw.get("status", {}).get("addresses", [])
            ip = addresses[0].get("value", "") if addresses else ""
            
            for listener in gw.get("spec", {}).get("listeners", []):
                listener_name = listener.get("name")
                listener_port = listener.get("port")
                listener_protocol = listener.get("protocol")
                listener_obj = {
                    "gatewayName": gw_name,
                    "namespace": ns,
                    "ip": ip,
                    "listenerName": listener_name,
                    "port": listener_port,
                    "protocol": listener_protocol,
                    "kind": gw.get("kind"),
                    "routes": []
                }

                # aggiungi L4Route collegate a questo listener
                for item in l4_data.get("items", []):
                    for parent in item.get("spec", {}).get("parentRefs", []):
                        if parent.get("name") == gw_name and parent.get("sectionName") == listener_name:
                            # Estrai backends con namespace
                            backends = []
                            for rule in item["spec"].get("rules", []):
                                for backend in rule.get("backendRefs", []):
                                    backend_ns = backend.get("namespace", "")
                                    backend_name = backend.get("name", "")
                                    backend_port = backend.get("port", "")
                                    # Formato: namespace/service:port
                                    backends.append(f"{backend_ns}/{backend_name}:{backend_port}")
                            
                            listener_obj["routes"].append({
                                "type": "L4Route",
                                "name": item["metadata"]["name"],
                                "protocol": item["spec"].get("protocol", ""),
                                "backends": backends
                            })

                # aggiungi HTTPRoute collegate a questo listener
                for item in http_data.get("items", []):
                    for parent in item.get("spec", {}).get("parentRefs", []):
                        if parent.get("name") == gw_name and parent.get("sectionName") == listener_name:
                            for rule in item["spec"].get("rules", []):
                                # Estrai backends con namespace
                                backends = []
                                for backend in rule.get("backendRefs", []):
                                    backend_ns = backend.get("namespace", "")
                                    backend_name = backend.get("name", "")
                                    backend_port = backend.get("port", "")
                                    # Formato: namespace/service:port
                                    backends.append(f"{backend_ns}/{backend_name}:{backend_port}")
                                
                                for match in rule.get("matches", [{}]):
                                    listener_obj["routes"].append({
                                        "type": "HTTPRoute",
                                        "name": item["metadata"]["name"],
                                        "match": match,
                                        "backends": backends
                                    })

                gateways_result.append(listener_obj)

        return {"gateways": gateways_result}

    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

# --- API: tutte le firewall policies con associazioni ---
@app.get("/api/all-firewall-policies")
def get_all_firewall_policies():
    try:
        # Recupera tutte le F5BigFwPolicy
        fw_data = run_kubectl(["kubectl", "get", "F5BigFwPolicy.k8s.f5net.com", "-A", "-o", "json"]) or {}
        
        # Recupera BNKSecPolicy per associazioni ingress
        bnk_data = run_kubectl(["kubectl", "get", "BNKSecPolicy.gateway.k8s.f5net.com", "-A", "-o", "json"]) or {}
        
        # Recupera Egress per associazioni egress
        egress_data = run_kubectl(["kubectl", "get", "F5SPKEgress.k8s.f5net.com", "-A", "-o", "json"]) or {}
        
        # Recupera Gateway per ottenere IP e porta
        gw_data = run_kubectl(["kubectl", "get", "gateway.gateway.networking.k8s.io", "-A", "-o", "json"]) or {}
        
        policies_list = []
        
        for fw in fw_data.get("items", []):
            policy_name = fw["metadata"]["name"]
            policy_ns = fw["metadata"]["namespace"]
            
            # Estrai regole
            rules = []
            for rule in fw.get("spec", {}).get("rule", []):
                rules.append({
                    "name": rule.get("name", ""),
                    "action": rule.get("action", ""),
                    "ipProtocol": rule.get("ipProtocol", ""),
                    "source": ", ".join(rule.get("source", {}).get("addresses", [])),
                    "sourcePorts": ", ".join(rule.get("source", {}).get("ports", [])),
                    "destination": ", ".join(rule.get("destination", {}).get("addresses", [])),
                    "destinationPorts": ", ".join(rule.get("destination", {}).get("ports", [])),
                    "logging": str(rule.get("logging", False))
                })
            
            # Cerca associazioni INGRESS (BNKSecPolicy)
            ingress_associations = []
            for bnk in bnk_data.get("items", []):
                for ext in bnk.get("spec", {}).get("extensionRefs", []):
                    if ext.get("kind") == "F5BigFwPolicy" and ext.get("name") == policy_name:
                        # Trovata associazione
                        for target in bnk.get("spec", {}).get("targetRefs", []):
                            if target.get("kind") == "Gateway":
                                gw_name = target.get("name")
                                listener_name = target.get("sectionName")
                                gw_ns = bnk["metadata"]["namespace"]
                                
                                # Trova IP e porta del gateway
                                ip = ""
                                port = ""
                                protocol = ""
                                for gw in gw_data.get("items", []):
                                    if gw["metadata"]["name"] == gw_name and gw["metadata"]["namespace"] == gw_ns:
                                        ip = gw.get("status", {}).get("addresses", [{}])[0].get("value", "")
                                        for listener in gw.get("spec", {}).get("listeners", []):
                                            if listener.get("name") == listener_name:
                                                port = listener.get("port", "")
                                                protocol = listener.get("protocol", "")
                                                break
                                        break
                                
                                ingress_associations.append({
                                    "type": "ingress",
                                    "app": f"{gw_name}/{listener_name}",
                                    "namespace": gw_ns,
                                    "ip": ip,
                                    "port": port,
                                    "protocol": protocol,
                                    "gatewayIp": ip  # Aggiungo anche come gatewayIp per usarlo nel DST IP
                                })
            
            # Cerca associazioni EGRESS
            egress_associations = []
            for egress in egress_data.get("items", []):
                if egress.get("spec", {}).get("firewallEnforcedPolicy") == policy_name:
                    app_namespaces = egress.get("spec", {}).get("pseudoCNIConfig", {}).get("namespaces", [])
                    
                    # Per egress, usa "any" come protocollo generico (le regole hanno protocolli specifici)
                    protocol = "any"
                    
                    egress_associations.append({
                        "type": "egress",
                        "app": egress["metadata"]["name"],
                        "namespace": ", ".join(app_namespaces),
                        "ip": "-",
                        "port": "-",
                        "protocol": protocol,
                        "gatewayIp": "-"
                    })
            
            # Combina tutte le associazioni
            all_associations = ingress_associations + egress_associations
            
            if not all_associations:
                # Policy non associata
                policies_list.append({
                    "policyName": policy_name,
                    "policyNamespace": policy_ns,
                    "type": "unassociated",
                    "app": "-",
                    "namespace": policy_ns,
                    "ip": "-",
                    "port": "-",
                    "protocol": "-",
                    "gatewayIp": "-",
                    "rules": rules
                })
            else:
                # Crea una entry per ogni associazione
                for assoc in all_associations:
                    policies_list.append({
                        "policyName": policy_name,
                        "policyNamespace": policy_ns,
                        "type": assoc["type"],
                        "app": assoc["app"],
                        "namespace": assoc["namespace"],
                        "ip": assoc["ip"],
                        "port": assoc["port"],
                        "protocol": assoc["protocol"],
                        "rules": rules
                    })
        
        return {"policies": policies_list}
    
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

# --- API: recupera egress configurations ---
@app.get("/api/egress")
def get_egress():
    try:
        egress_data = run_kubectl(["kubectl", "get", "F5SPKEgress.k8s.f5net.com", "-A", "-o", "json"]) or {}
        
        egress_list = []
        for item in egress_data.get("items", []):
            egress_list.append({
                "name": item["metadata"]["name"],
                "appNamespaces": ", ".join(item.get("spec", {}).get("pseudoCNIConfig", {}).get("namespaces", [])),
                "snatType": item.get("spec", {}).get("snatType", ""),
                "snatpool": item.get("spec", {}).get("egressSnatpool", ""),
                "firewallPolicy": item.get("spec", {}).get("firewallEnforcedPolicy", ""),
                "namespace": item["metadata"]["namespace"]  # Per recuperare le risorse
            })
        
        return {"egress": egress_list}
    
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

# --- API: recupera SNAT pool details ---
@app.get("/api/snatpools")
def get_snatpools():
    try:
        snat_data = run_kubectl(["kubectl", "get", "F5SPKSnatpool.k8s.f5net.com", "-A", "-o", "json"]) or {}
        
        snatpools_map = {}
        for item in snat_data.get("items", []):
            name = item["metadata"]["name"]
            namespace = item["metadata"]["namespace"]
            key = f"{namespace}|{name}"
            
            # Flatten addressList
            addresses = []
            for addr_group in item.get("spec", {}).get("addressList", []):
                addresses.extend(addr_group)
            
            snatpools_map[key] = {
                "name": name,
                "namespace": namespace,
                "addresses": addresses
            }
        
        return {"snatpools": snatpools_map}
    
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

# --- API: recupera firewall policies (già esistente ma la modifico per egress) ---
@app.get("/api/firewall-policies")
def get_firewall_policies():
    try:
        fw_data = run_kubectl(["kubectl", "get", "F5BigFwPolicy.k8s.f5net.com", "-A", "-o", "json"]) or {}
        
        policies_map = {}
        for item in fw_data.get("items", []):
            name = item["metadata"]["name"]
            namespace = item["metadata"]["namespace"]
            key = f"{namespace}|{name}"
            
            rules = []
            for rule in item.get("spec", {}).get("rule", []):
                rules.append({
                    "name": rule.get("name", ""),
                    "action": rule.get("action", ""),
                    "ipProtocol": rule.get("ipProtocol", ""),
                    "source": ", ".join(rule.get("source", {}).get("addresses", [])),
                    "destination": ", ".join(rule.get("destination", {}).get("addresses", [])),
                    "ports": ", ".join(rule.get("destination", {}).get("ports", [])),
                    "logging": str(rule.get("logging", False))
                })
            
            policies_map[key] = {
                "name": name,
                "namespace": namespace,
                "rules": rules
            }
        
        return {"policies": policies_map}
    
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

# --- API: recupera policy di sicurezza per listener ---
@app.get("/api/security-policies")
def get_security_policies():
    try:
        # Recupera BNKSecPolicy
        bnk_data = run_kubectl(["kubectl", "get", "BNKSecPolicy.gateway.k8s.f5net.com", "-A", "-o", "json"]) or {}
        
        # Recupera F5BigFwPolicy
        fw_data = run_kubectl(["kubectl", "get", "F5BigFwPolicy.k8s.f5net.com", "-A", "-o", "json"]) or {}
        
        # Mappa: (gateway_name, listener_name, namespace) -> lista di policy
        policies_map = {}
        
        for bnk in bnk_data.get("items", []):
            bnk_ns = bnk["metadata"]["namespace"]
            
            # Estrai i targetRefs (gateway e listener)
            for target in bnk.get("spec", {}).get("targetRefs", []):
                if target.get("kind") == "Gateway":
                    gw_name = target.get("name")
                    listener_name = target.get("sectionName")
                    
                    key = f"{gw_name}|{listener_name}|{bnk_ns}"
                    
                    if key not in policies_map:
                        policies_map[key] = []
                    
                    # Estrai le extensionRefs (le policy F5BigFwPolicy)
                    for ext in bnk.get("spec", {}).get("extensionRefs", []):
                        if ext.get("kind") == "F5BigFwPolicy":
                            policy_name = ext.get("name")
                            
                            # Trova la policy corrispondente
                            for fw in fw_data.get("items", []):
                                if fw["metadata"]["name"] == policy_name and fw["metadata"]["namespace"] == bnk_ns:
                                    # Estrai le regole
                                    rules = []
                                    for rule in fw.get("spec", {}).get("rule", []):
                                        rules.append({
                                            "name": rule.get("name", ""),
                                            "action": rule.get("action", ""),
                                            "ipProtocol": rule.get("ipProtocol", ""),
                                            "source": ", ".join(rule.get("source", {}).get("addresses", [])),
                                            "destination": ", ".join(rule.get("destination", {}).get("addresses", [])),
                                            "ports": ", ".join(rule.get("destination", {}).get("ports", [])),
                                            "logging": str(rule.get("logging", False))
                                        })
                                    
                                    policies_map[key].append({
                                        "policyName": policy_name,
                                        "namespace": bnk_ns,
                                        "rules": rules
                                    })
        
        return {"policies": policies_map}
    
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
