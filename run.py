"""
run.py - Main CLI Driver for AegisScan-ML
"""
import os
import json
import argparse
import joblib
from rich.console import Console
from rich.table import Table

from core.requester import Requester
from core.crawler import Crawler
from modules.sqli import SQLiModule
from modules.xss import XSSModule
from ml.features import HTTPFeatureExtractor

console = Console()

def main():
    parser = argparse.ArgumentParser(description="AegisScan-ML: DAST & ML Vulnerability Scanner")
    parser.add_argument("--url", required=True, help="Target URL (e.g. http://127.0.0.1:8080/vulnerabilities/sqli/ or http://127.0.0.1:5000)")
    parser.add_argument("--depth", type=int, default=1, help="Crawl depth (default: 1)")
    parser.add_argument("--model", default="ml/model.pkl", help="Path to trained model")
    args = parser.parse_args()

    console.print("\n[bold cyan]╔═══════════════════════════════════════════════════════╗[/bold cyan]")
    console.print("[bold cyan]║   AegisScan-ML: DAST & Payload Intelligence Engine    ║[/bold cyan]")
    console.print("[bold cyan]╚═══════════════════════════════════════════════════════╝[/bold cyan]\n")

    # 1. Initialize Crawler & Requester
    requester = Requester()
    crawler = Crawler(target_base_url=args.url, requester=requester, max_depth=args.depth)
    
    with console.status("[bold green]Crawling and mapping attack surface..."):
        targets = crawler.crawl()

    console.print(f"[+] Attack Surface Mapped: [bold green]{len(targets)}[/bold green] potential injection points discovered.")

    # 2. Initialize Audit Probers
    probers = [SQLiModule(requester), XSSModule(requester)]
    raw_findings = []
    
    with console.status("[bold yellow]Executing Active Vulnerability Probes..."):
        for target in targets:
            for prober in probers:
                raw_findings.extend(prober.scan(target))

    console.print(f"[+] Generated [bold yellow]{len(raw_findings)}[/bold yellow] raw probe interactions.")

    # 3. Machine Learning Verification Filter
    ml_verified_findings = []
    if os.path.exists(args.model):
        try:
            model = joblib.load(args.model)
        except Exception:
            import pickle
            with open(args.model, "rb") as mf:
                model = pickle.load(mf)
        extractor = HTTPFeatureExtractor()
        
        with console.status("[bold magenta]Evaluating transactions through ML Classifier..."):
            for finding in raw_findings:
                features = extractor.extract(
                    payload=finding["payload"],
                    status_code=finding["status_code"],
                    response_body=finding["response_body"]
                )
                feat_input = features.reshape(1, -1) if hasattr(features, "reshape") else [features]
                pred = model.predict(feat_input)[0]
                prob = model.predict_proba(feat_input)[0][1]
                
                # If classified as positive exploit indicator
                if pred == 1 and prob >= 0.70:
                    finding["ml_confidence"] = f"{prob * 100:.1f}%"
                    ml_verified_findings.append(finding)
    else:
        console.print("[bold red][!] Model not found. Displaying unverified findings.[/bold red]")
        ml_verified_findings = raw_findings

    # 4. Render Results Table
    table = Table(title="AegisScan Audit Results", show_lines=True)
    table.add_column("Type", style="bold red")
    table.add_column("Severity", style="bold yellow")
    table.add_column("Parameter", style="cyan")
    table.add_column("ML Confidence", style="green")
    table.add_column("cURL Reproduction PoC", style="dim")

    for f in ml_verified_findings:
        curl_poc = f"curl -X GET '{f['url']}?{f['parameter']}={f['payload']}'"
        table.add_row(
            f["vuln_type"],
            f["severity"],
            f["parameter"],
            f.get("ml_confidence", "N/A"),
            curl_poc
        )

    console.print(table)
    
    # 5. Export JSON Artifact
    with open("scan_report.json", "w", encoding="utf-8") as out:
        json.dump(ml_verified_findings, out, indent=2)
    console.print(f"\n[+] Detailed report exported to [bold green]scan_report.json[/bold green]\n")

if __name__ == "__main__":
    main()
