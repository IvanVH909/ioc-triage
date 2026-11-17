import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import evaluate  # noqa: E402
import triaje  # noqa: E402


class ClassifyTests(unittest.TestCase):
    def test_tipos(self):
        self.assertEqual(triaje.classify("8.8.8.8"), "ip")
        self.assertEqual(triaje.classify("2001:4860:4860::8888"), "ip")
        self.assertEqual(triaje.classify("example.com"), "domain")
        self.assertEqual(triaje.classify("a" * 32), "hash")
        self.assertEqual(triaje.classify("a" * 40), "hash")
        self.assertEqual(triaje.classify("A" * 64), "hash")

    def test_invalido(self):
        for bad in ["", "not an ioc", "999.1.1.1.1", "http://x.com/a", "a" * 33]:
            with self.assertRaises(ValueError):
                triaje.classify(bad)


class BaselineTests(unittest.TestCase):
    def ev(self, abuse=None, vt_mal=None, vt_sus=0):
        return {
            "abuseipdb": None if abuse is None else {"abuse_score": abuse},
            "virustotal": None if vt_mal is None else {"malicious": vt_mal, "suspicious": vt_sus},
            "errors": [],
        }

    def test_sin_datos_es_unknown(self):
        self.assertEqual(triaje.baseline_verdict(self.ev()), "unknown")

    def test_malicious(self):
        self.assertEqual(triaje.baseline_verdict(self.ev(abuse=90, vt_mal=0)), "malicious")
        self.assertEqual(triaje.baseline_verdict(self.ev(abuse=0, vt_mal=6)), "malicious")

    def test_suspicious(self):
        self.assertEqual(
            triaje.baseline_verdict(self.ev(abuse=30, vt_mal=0)),
            "suspicious"
        )

        self.assertEqual(
            triaje.baseline_verdict(self.ev(abuse=0, vt_mal=2)),
            "suspicious"
        )

    def test_benign(self):
        self.assertEqual(triaje.baseline_verdict(self.ev(abuse=0, vt_mal=0)), "benign")


class NormalizeTests(unittest.TestCase):
    def test_abuseipdb(self):
        raw = {"data": {"abuseConfidenceScore": 77, "totalReports": 5, "countryCode": "ES"}}
        n = triaje.normalize_abuseipdb(raw)
        self.assertEqual(n["abuse_score"], 77)
        self.assertEqual(n["country"], "ES")

    def test_virustotal_tolera_campos_ausentes(self):
        n = triaje.normalize_virustotal({"data": {"attributes": {}}})
        self.assertEqual(n["malicious"], 0)


class LlmParsingTests(unittest.TestCase):
    def test_json_limpio(self):
        out = triaje.parse_llm_json('{"verdict":"malicious","confidence":"high","summary":"x","next_steps":["a","b"]}')
        self.assertEqual(out["verdict"], "malicious")
        self.assertEqual(out["next_steps"], ["a", "b"])

    def test_json_con_bloque_de_codigo(self):
        out = triaje.parse_llm_json('```json\n{"verdict":"benign","confidence":"low","summary":"s","next_steps":[]}\n```')
        self.assertEqual(out["verdict"], "benign")

    def test_veredicto_inventado_pasa_a_unknown(self):
        out = triaje.parse_llm_json('{"verdict":"apocalipsis","summary":"s"}')
        self.assertEqual(out["verdict"], "unknown")

    def test_sin_json_lanza_error(self):
        with self.assertRaises(ValueError):
            triaje.parse_llm_json("lo siento, no puedo")


class TriageFlowTests(unittest.TestCase):
    def test_offline_sin_llm(self):
        r = triaje.triage("203.0.113.7", offline=True, use_llm=False)
        self.assertEqual(r["baseline_verdict"], "malicious")
        self.assertIsNone(r["llm"])

    def test_offline_sin_fixture_da_unknown(self):
        r = triaje.triage("203.0.113.99", offline=True, use_llm=False)
        self.assertEqual(r["baseline_verdict"], "unknown")
        self.assertTrue(r["evidence"]["errors"])

    def test_llm_mockeado(self):
        fake = {"candidates": [{"content": {"parts": [{"text": '{"verdict":"malicious","confidence":"high","summary":"ok","next_steps":["bloquear"]}'}]}}]}
        with mock.patch.dict("os.environ", {"GEMINI_API_KEY": "x"}), \
             mock.patch.object(triaje, "http_json", return_value=fake):
            r = triaje.triage("203.0.113.7", offline=True, use_llm=True)
        self.assertEqual(r["llm"]["verdict"], "malicious")

    def test_fallo_del_llm_no_rompe_el_triaje(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            r = triaje.triage("203.0.113.7", offline=True, use_llm=True)
        self.assertIn("error", r["llm"])
        self.assertEqual(r["baseline_verdict"], "malicious")

    def test_ip_privada_no_se_consulta(self):
        with mock.patch.object(triaje, "http_json") as m:
            r = triaje.triage("192.168.1.10", use_llm=False)
        m.assert_not_called()
        self.assertEqual(r["baseline_verdict"], "unknown")


class EvaluateTests(unittest.TestCase):
    def test_is_correct(self):
        self.assertTrue(evaluate.is_correct("malicious", "suspicious"))
        self.assertFalse(evaluate.is_correct("malicious", "benign"))
        self.assertTrue(evaluate.is_correct("benign", "unknown"))
        self.assertFalse(evaluate.is_correct("benign", "malicious"))

    def test_metrics(self):
        rows = [
            {"expected": "malicious", "baseline": "malicious"},
            {"expected": "malicious", "baseline": "benign"},   # FN
            {"expected": "benign", "baseline": "suspicious"},  # FP
            {"expected": "benign", "baseline": "benign"},
        ]
        m = evaluate.metrics(rows, "baseline")
        self.assertEqual((m["correct"], m["fp"], m["fn"]), (2, 1, 1))


if __name__ == "__main__":
    unittest.main()
