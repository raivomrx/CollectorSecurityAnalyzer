"""Privacy-minimized, family-grouped vulnerability-intelligence gap worklist."""

from collections import Counter
from typing import Any


def intelligence_worklist(endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Rank unresolved families by eligible impact, relevance and repetition."""
    grouped = {}
    for index, endpoint in enumerate(endpoints):
        seen = set()
        for software in endpoint.get("softwareResults", []):
            pipe = software.get("cvePipeline", {})
            if pipe.get("terminalStatus") == "COMPLETED":
                continue
            vendor = str(software.get("normalizedVendor") or software.get("publisher") or "Unknown")
            product = str(software.get("normalizedProduct") or software.get("displayName") or "Unknown")
            version = str(software.get("normalizedVersion") or software.get("displayVersion") or "Unknown")
            identity = (vendor.casefold(), product.casefold(), version, software.get("architecture"))
            if identity in seen:
                continue
            seen.add(identity)
            row = grouped.setdefault(identity[:2], {
                "canonicalVendor": vendor, "canonicalProduct": product,
                "displayVariants": set(), "versions": set(), "endpointInstanceCount": 0,
                "eligibleInstanceCount": 0, "endpoints": set(), "terminalReasons": Counter(),
                "candidateAuthoritativeSources": set(), "candidateCpeFamilies": set(),
                "confidenceBlockers": set(), "retryable": False,
            })
            row["displayVariants"].add(str(software.get("displayName") or product))
            row["versions"].add(version)
            row["endpointInstanceCount"] += 1
            row["eligibleInstanceCount"] += int(pipe.get("eligibilityStatus") == "ELIGIBLE")
            row["endpoints"].add(index)
            row["terminalReasons"][str(pipe.get("terminalReasonCode") or "NO_AUTHORITATIVE_MAPPING")] += 1
            trace = pipe.get("discoveryTrace") or {}
            if trace.get("aliasSource"):
                row["candidateAuthoritativeSources"].add(trace["aliasSource"])
            if pipe.get("cpe"):
                row["candidateCpeFamilies"].add(pipe["cpe"])
            for candidate in trace.get("topCandidates", []):
                if candidate.get("cpe"):
                    row["candidateCpeFamilies"].add(candidate["cpe"])
                if candidate.get("rejectionReason"):
                    row["confidenceBlockers"].add(candidate["rejectionReason"])
            if pipe.get("failureReason"):
                row["confidenceBlockers"].add(pipe["failureReason"])
            row["retryable"] |= bool(pipe.get("retryable"))
    result = []
    for row in grouped.values():
        reasons = dict(sorted(row.pop("terminalReasons").items()))
        row["terminalReasons"] = reasons
        row["endpointCount"] = len(row.pop("endpoints"))
        for key in ("displayVariants", "versions", "candidateAuthoritativeSources", "candidateCpeFamilies", "confidenceBlockers"):
            row[key] = sorted(row[key])
        row["securityRelevance"] = any(token in row["canonicalProduct"].casefold() for token in (
            "browser", "chrome", "firefox", "edge", "webview", "onedrive", "teams", "code", "office",
            "malware", "defender", "security", "vpn", "remote", "reader", "acrobat", "zip", "driver",
        ))
        row["recommendedResolverAction"] = (
            "Validate effective edition/platform and authoritative affected-version bounds."
            if any(key in reasons for key in ("APPLICABILITY_INCOMPLETE", "EDITION_UNKNOWN", "CPE_VERSION_NA")) else
            "Verify exact vendor/product/component identity against the authoritative product catalog."
        )
        result.append(row)
    return sorted(result, key=lambda row: (-row["eligibleInstanceCount"], -row["securityRelevance"],
                                         -row["endpointCount"], sorted(row["terminalReasons"]),
                                         row["canonicalVendor"], row["canonicalProduct"]))
