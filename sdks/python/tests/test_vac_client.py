import unittest
from unittest.mock import patch, MagicMock
import json
from vac_client import VACClient, VACResponse, VACError

class TestVACClient(unittest.TestCase):
    def setUp(self):
        self.client = VACClient(
            sidecar_url="http://localhost:3000",
            root_biscuit="test-root-biscuit"
        )

    def test_init_defaults(self):
        c = VACClient(root_biscuit="x")
        self.assertEqual(c.sidecar_url, "http://localhost:3000")
        self.assertIsNotNone(c.correlation_id)
        self.assertEqual(c.receipts, [])

    def test_init_custom(self):
        cid = "custom-cid"
        c = VACClient(sidecar_url="http://test:1234/", root_biscuit="x", correlation_id=cid)
        self.assertEqual(c.sidecar_url, "http://test:1234")  # rstrip("/") handled? Let's check impl
        self.assertEqual(c.correlation_id, cid)

    def test_build_headers(self):
        self.client.receipts = ["r1", "r2"]
        headers = self.client._build_headers()
        # Should contain Auth, Correlation-ID, Content-Type (default include=True), and 2 Receipts
        auth = next(v for k, v in headers if k == "Authorization")
        self.assertEqual(auth, "Bearer test-root-biscuit")
        
        receipts = [v for k, v in headers if k == "X-VAC-Receipt"]
        self.assertEqual(receipts, ["r1", "r2"])

    def test_build_headers_no_content_type(self):
        headers = self.client._build_headers(include_content_type=False)
        ct = [v for k, v in headers if k == "Content-Type"]
        self.assertEqual(ct, [])

    @patch("vac_client.httpx")
    def test_request_httpx_json(self, mock_httpx):
        # Setup mock response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.text = '{"ok": true}'
        
        mock_client_instance = MagicMock()
        mock_client_instance.request.return_value = mock_response
        mock_client_instance.__enter__.return_value = mock_client_instance
        mock_httpx.Client.return_value = mock_client_instance

        # Call
        resp = self.client.post("/test", json={"a": 1})

        # Verify
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"ok": True})
        
        # Verify call args
        mock_client_instance.request.assert_called_once()
        args, kwargs = mock_client_instance.request.call_args
        self.assertEqual(kwargs["json"], {"a": 1})
        self.assertIsNone(kwargs.get("content"))  # Should not pass content when json is used

    def test_receipt_extraction(self):
        # Test that receipt header is extracted and added to self.receipts
        with patch("vac_client.httpx") as mock_httpx:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            # Mock headers.get behavior
            mock_resp.headers.get.side_effect = lambda k: "new-receipt" if k.lower() == "x-vac-receipt" else None
            mock_resp.text = ""
            
            mock_client = MagicMock()
            mock_client.request.return_value = mock_resp
            mock_client.__enter__.return_value = mock_client
            mock_httpx.Client.return_value = mock_client

            self.client.post("/step1")
            
            self.assertIn("new-receipt", self.client.receipts)

    def test_vac_error_properties(self):
        # Test is_missing_receipt logic
        err = VACError(403, "some prior_event missing")
        self.assertTrue(err.is_missing_receipt)
        self.assertTrue(err.is_policy_violation)

        err2 = VACError(403, "Must complete prior step")
        self.assertTrue(err2.is_missing_receipt) # Should match "prior step"

        err3 = VACError(403, "Receipt expired")
        self.assertTrue(err3.is_expired)
        
        err4 = VACError(409, "Correlation mismatch")
        self.assertTrue(err4.is_correlation_mismatch)

    def test_response_json_empty(self):
        resp = VACResponse(200, {}, "")
        self.assertIsNone(resp.json())
        
        resp2 = VACResponse(200, {}, "{}")
        self.assertEqual(resp2.json(), {})

if __name__ == "__main__":
    unittest.main()
