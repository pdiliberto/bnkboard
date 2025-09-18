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
        ns_output = subprocess.check_output(
            ["kubectl", "get", "ns", "-o", "json"], text=True
        )
        ns_data = yaml.safe_load(ns_output)

        gateways = []
        for item in ns_data.get("items", []):
            ns = item["metadata"]["name"]

            try:
                # Recupero gateway del namespace
                gw_output = subprocess.check_output(
                    ["kubectl", "get", "gateway.gateway.networking.k8s.io", "-n", ns, "-o", "json"],
                    text=True
                )
                gw_data = yaml.safe_load(gw_output)

                for gw in gw_data.get("items", []):
                    gw_name = gw["metadata"]["name"]
                    spec = gw.get("spec", {})
                    status = gw.get("status", {})
                    listeners = spec.get("listeners", [])

                    # Prendi IP da status (dinamico)
                    ip = ""
                    if "addresses" in status and status["addresses"]:
                        ip = status["addresses"][0].get("value", "")

                    # Inizializza oggetto gateway
                    gw_entry = {
                        "namespace": ns,
                        "name": gw_name,
                        "ip": ip,
                        "listeners": [],
                        "policies": []
                    }

                    # --- Recupera policies che referenziano questo gateway ---
                    try:
                        pol_output = subprocess.check_output(
                            ["kubectl", "get", "f5bigfwpolicy.k8s.f5net.com", "-o", "json"],
                            text=True
                        )
                        pol_data = yaml.safe_load(pol_output)

                        for pol in pol_data.get("items", []):
                            target_refs = pol.get("spec", {}).get("targetRefs", [])
                            for tref in target_refs:
                                if tref.get("kind") == "Gateway" and tref.get("name") == gw_name and tref.get("namespace", ns) == ns:
                                    gw_entry["policies"].append({
                                        "name": pol["metadata"]["name"],
                                        "reason": pol.get("status", {}).get("conditions", [{}])[0].get("reason", ""),
                                        "message": pol.get("status", {}).get("conditions", [{}])[0].get("message", "")
                                    })
                    except subprocess.CalledProcessError:
                        pass

                    # --- Aggiungi listeners e route collegate ---
                    for listener in listeners:
                        listener_entry = {
                            "name": listener.get("name", ""),
                            "port": listener.get("port", ""),
                            "protocol": listener.get("protocol", ""),
                            "routes": []
                        }

                        # Recupera L4Route e HTTPRoute
                        for route_kind, route_cmd in [
                            ("L4Route", ["kubectl", "get", "l4route.gateway.k8s.f5net.com", "-n", ns, "-o", "json"]),
                            ("HTTPRoute", ["kubectl", "get", "httproute.gateway.networking.k8s.io", "-n", ns, "-o", "json"]),
                        ]:
                            try:
                                route_output = subprocess.check_output(route_cmd, text=True)
                                route_data = yaml.safe_load(route_output)

                                for route in route_data.get("items", []):
                                    parent_refs = route.get("spec", {}).get("parentRefs", [])
                                    for pref in parent_refs:
                                        if pref.get("name") == gw_name and pref.get("sectionName") == listener.get("name"):
                                            # Aggiungi route al listener
                                            route_entry = {
                                                "kind": route_kind,
                                                "name": route["metadata"]["name"],
                                                "matches": [],
                                                "backends": []
                                            }

                                            if route_kind == "L4Route":
                                                for rule in route.get("spec", {}).get("rules", []):
                                                    for be in rule.get("backendRefs", []):
                                                        route_entry["backends"].append(f"{be.get('name')}:{be.get('port')}")
                                            elif route_kind == "HTTPRoute":
                                                for rule in route.get("spec", {}).get("rules", []):
                                                    # Matches
                                                    for match in rule.get("matches", []):
                                                        if "headers" in match:
                                                            for h in match["headers"]:
                                                                route_entry["matches"].append(f"{h.get('name')}: {h.get('value')}")
                                                        if "path" in match:
                                                            route_entry["matches"].append(f"{match['path']['type']}: {match['path']['value']}")
                                                    # Backends
                                                    for be in rule.get("backendRefs", []):
                                                        route_entry["backends"].append(f"{be.get('name')}:{be.get('port')}")

                                            listener_entry["routes"].append(route_entry)
                            except subprocess.CalledProcessError:
                                pass

                        gw_entry["listeners"].append(listener_entry)

                    gateways.append(gw_entry)

            except subprocess.CalledProcessError:
                pass

        return {"gateways": gateways}

    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

