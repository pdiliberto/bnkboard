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

@app.get("/api/firewall-rules")
def get_firewall_rules():
    try:
        output = subprocess.check_output(
            ["kubectl", "get", "f5bigfwpolicy.k8s.f5net.com", "-o", "json"],
            text=True
        )
        data = yaml.safe_load(output)

        rules = []
        for item in data.get("items", []):
            pol_name = item["metadata"]["name"]
            creation_ts = item["metadata"].get("creationTimestamp", "")
            target_refs = item.get("spec", {}).get("targetRefs", [])

            target_names = [t.get("name", "") for t in target_refs]
            target_display = "\n".join(target_names)

            for rule in item.get("spec", {}).get("rule", []):
                rules.append({
                    "polname": pol_name,
                    "target": target_display,
                    "ruleName": rule.get("name", ""),
                    "protocol": rule.get("ipProtocol", ""),
                    "source": "\n".join(rule.get("source", {}).get("addresses", [])),
                    "destination": "\n".join(rule.get("destination", {}).get("addresses", [])),
                    "ports": "\n".join(rule.get("destination", {}).get("ports", [])),
                    "action": rule.get("action", ""),
                    "logging": str(rule.get("logging", "")),
                    "description": rule.get("description", ""),
                    "timestamp": creation_ts
                })
        return rules
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

# --- API: lista namespaces con almeno un gateway ---
@app.get("/api/namespaces")
def list_namespaces():
    try:
        ns_output = subprocess.check_output(
            ["kubectl", "get", "ns", "-o", "json"], text=True
        )
        ns_data = yaml.safe_load(ns_output)

        namespaces = []
        for item in ns_data.get("items", []):
            ns = item["metadata"]["name"]

            try:
                gw_output = subprocess.check_output(
                    ["kubectl", "get", "gateway.gateway.networking.k8s.io", "-n", ns, "-o", "json"],
                    text=True
                )
                gw_data = yaml.safe_load(gw_output)
                if gw_data.get("items"):
                    namespaces.append(ns)
            except subprocess.CalledProcessError:
                pass

        return {"namespaces": namespaces}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

# --- API: policies per namespace ---
@app.get("/api/policies/{namespace}")
def get_policies_by_namespace(namespace: str):
    try:
        # Recupera i gateway nel namespace
        gw_output = subprocess.check_output(
            ["kubectl", "get", "gateway.gateway.networking.k8s.io", "-n", namespace, "-o", "json"],
            text=True
        )
        gw_data = yaml.safe_load(gw_output)
        gw_names = [item["metadata"]["name"] for item in gw_data.get("items", [])]

        # Recupera tutte le policy
        pol_output = subprocess.check_output(
            ["kubectl", "get", "f5bigfwpolicy.k8s.f5net.com", "-o", "json"],
            text=True
        )
        pol_data = yaml.safe_load(pol_output)

        matched_policies = []
        for pol in pol_data.get("items", []):
            target_refs = pol.get("spec", {}).get("targetRefs", [])
            for tref in target_refs:
                if tref.get("kind") == "Gateway" and tref.get("name") in gw_names:
                    # Aggiunge info gateway
                    gw_item = next((g for g in gw_data.get("items", []) if g["metadata"]["name"] == tref["name"]), None)
                    if gw_item:
                        listener = gw_item.get("spec", {}).get("listeners", [{}])[0]
                        allowed_kind = listener.get("allowedRoutes", {}).get("kinds", [{}])[0].get("kind", "")
                        address_value = gw_item.get("spec", {}).get("addresses", [{}])[0].get("value", "")
                        pol["gateway"] = {
                            "name": gw_item["metadata"]["name"],
                            "ip": address_value,
                            "port": listener.get("port", ""),
                            "protocol": listener.get("protocol", ""),
                            "kind": allowed_kind
                        }
                    matched_policies.append(pol)

        return {"policies": matched_policies}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

# --- NUOVA API: elenco Gateway con listener e route ---
@app.get("/api/gateways")
def list_gateways():
    try:
        # recupera namespaces
        ns_data = run_kubectl(["kubectl", "get", "ns", "-o", "json"])
        if not ns_data:
            return {"gateways": []}

        # recupera tutte le L4Route e HTTPRoute globali
        l4_data = run_kubectl(["kubectl", "get", "l4route.gateway.k8s.f5net.com", "-A", "-o", "json"]) or {}
        http_data = run_kubectl(["kubectl", "get", "httproute.gateway.networking.k8s.io", "-A", "-o", "json"]) or {}

        gateways_result = []

        for ns_item in ns_data.get("items", []):
            ns = ns_item["metadata"]["name"]
            gw_data = run_kubectl(["kubectl", "get", "gateway.gateway.networking.k8s.io", "-n", ns, "-o", "json"])
            if not gw_data:
                continue

            for gw in gw_data.get("items", []):
                gw_name = gw["metadata"]["name"]
                ip = gw.get("status", {}).get("addresses", [{}])[0].get("value", "")
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
                                listener_obj["routes"].append({
                                    "type": "L4Route",
                                    "name": item["metadata"]["name"],
                                    "protocol": item["spec"].get("protocol", ""),
                                    "backends": [
                                        f"{b['name']}:{b['port']}" for r in item["spec"].get("rules", []) for b in r.get("backendRefs", [])
                                    ]
                                })

                    # aggiungi HTTPRoute collegate a questo listener
                    for item in http_data.get("items", []):
                        for parent in item.get("spec", {}).get("parentRefs", []):
                            if parent.get("name") == gw_name and parent.get("sectionName") == listener_name:
                                for rule in item["spec"].get("rules", []):
                                    for match in rule.get("matches", [{}]):
                                        listener_obj["routes"].append({
                                            "type": "HTTPRoute",
                                            "name": item["metadata"]["name"],
                                            "match": match,
                                            "backends": [f"{b['name']}:{b['port']}" for b in rule.get("backendRefs", [])]
                                        })

                    gateways_result.append(listener_obj)

        return {"gateways": gateways_result}

    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
