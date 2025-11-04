import sys, json, requests
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option

@Configuration()
class WhiffCommand(StreamingCommand):
    max_refs = Option(require=False, default=5)
    api = Option(require=False, default="http://127.0.0.1:8088/annotate")

    def stream(self, records):
        for r in records:
            ev = dict(r)
            try:
                resp = requests.post(self.api, json={"event":ev}, timeout=5)
                j = resp.json()
                helpo = j.get("help", {})
                r["whiff_summary"]    = helpo.get("summary")
                r["whiff_next_steps"] = "; ".join(helpo.get("next_steps", [])[:3])
                r["whiff_mitre"]      = "; ".join(m.get("technique","") for m in helpo.get("mitre", []))
                r["whiff_conf"]       = helpo.get("confidence")
                r["whiff_refs"]       = "; ".join((x.get("title") or x.get("url","")) for x in helpo.get("refs", [])[:int(self.max_refs)])
            except Exception as e:
                r["whiff_error"] = str(e)
            yield r

dispatch(WhiffCommand, sys.argv, sys.stdin, sys.stdout, __name__)
