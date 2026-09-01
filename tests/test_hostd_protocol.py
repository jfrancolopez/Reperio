#!/usr/bin/env python3

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from hostd import protocol

SOURCE_ID = "src_abcdefghijklmnop"
GENERATION = 7
SCHEMA_PATH = (
    Path(__file__).resolve().parents[1] / "scripts" / "schemas" / "hostd-protocol.schema.json"
)


def auth() -> dict[str, str]:
    return {"kind": protocol.AUTH_KIND, "principal": "reperio-api"}


def opaque(prefix: str) -> str:
    return f"{prefix}_abcdefghijklmnop"


def request(method: str, params: dict) -> dict:
    return {
        "schema_version": protocol.PROTOCOL_SCHEMA_VERSION,
        "request_id": "req-001",
        "auth": auth(),
        "method": method,
        "params": params,
    }


class HostdProtocolContractTests(unittest.TestCase):
    def test_list_devices_request_validates(self) -> None:
        message = request("list_devices", {})

        normalized = protocol.validate_request(message)

        self.assertEqual("list_devices", normalized["method"])

    def test_unknown_method_is_rejected(self) -> None:
        message = request("run_command", {"command": "lsblk"})

        with self.assertRaisesRegex(protocol.ProtocolError, "not allowlisted"):
            protocol.validate_request(message)

    def test_path_traversal_is_rejected(self) -> None:
        message = request(
            "inspect_safety",
            {"source_id": "../../dev/sda", "observed_generation": GENERATION},
        )

        with self.assertRaisesRegex(protocol.ProtocolError, "path-like"):
            protocol.validate_request(message, source_generations={SOURCE_ID: GENERATION})

    def test_bare_device_path_is_rejected(self) -> None:
        message = request(
            "inspect_safety",
            {"source_id": "/dev/sda", "observed_generation": GENERATION},
        )

        with self.assertRaisesRegex(protocol.ProtocolError, "path-like"):
            protocol.validate_request(message, source_generations={SOURCE_ID: GENERATION})

    def test_stale_device_generation_is_rejected(self) -> None:
        message = request(
            "inspect_safety",
            {"source_id": SOURCE_ID, "observed_generation": GENERATION - 1},
        )

        with self.assertRaisesRegex(protocol.ProtocolError, "stale"):
            protocol.validate_request(message, source_generations={SOURCE_ID: GENERATION})

    def test_boolean_generation_is_rejected(self) -> None:
        message = request(
            "inspect_safety",
            {"source_id": SOURCE_ID, "observed_generation": True},
        )

        with self.assertRaisesRegex(protocol.ProtocolError, "non-negative integer"):
            protocol.validate_request(message, source_generations={SOURCE_ID: GENERATION})

    def test_unknown_current_source_is_rejected(self) -> None:
        message = request(
            "inspect_safety",
            {"source_id": SOURCE_ID, "observed_generation": GENERATION},
        )

        with self.assertRaisesRegex(protocol.ProtocolError, "not current"):
            protocol.validate_request(message, source_generations={})

    def test_extra_launch_flags_are_rejected(self) -> None:
        message = request(
            "launch_scanner",
            {
                "source_id": SOURCE_ID,
                "observed_generation": GENERATION,
                "safety_inspection_id": opaque("safe"),
                "readonly_preparation_id": opaque("roprep"),
                "scan_case_id": opaque("case"),
                "scratch_separation_id": opaque("scratch"),
                "resource_profile": "default",
                "container_args": ["--privileged"],
            },
        )

        with self.assertRaisesRegex(protocol.ProtocolError, "unsupported key"):
            protocol.validate_request(message, source_generations={SOURCE_ID: GENERATION})

    def test_incompatible_schema_version_is_rejected(self) -> None:
        message = request("list_devices", {})
        message["schema_version"] = 2

        with self.assertRaisesRegex(protocol.ProtocolError, "schema_version"):
            protocol.validate_request(message)

    def test_auth_shape_is_required(self) -> None:
        message = request("list_devices", {})
        message["auth"] = {"kind": "bearer", "token": "secret"}

        with self.assertRaisesRegex(protocol.ProtocolError, "request.auth"):
            protocol.validate_request(message)

    def test_success_response_requires_result_only(self) -> None:
        message = {
            "schema_version": protocol.PROTOCOL_SCHEMA_VERSION,
            "request_id": "req-001",
            "ok": True,
            "result": {"devices": []},
        }

        normalized = protocol.validate_response(message)

        self.assertTrue(normalized["ok"])

    def test_failed_response_requires_error_only(self) -> None:
        message = {
            "schema_version": protocol.PROTOCOL_SCHEMA_VERSION,
            "request_id": "req-001",
            "ok": False,
            "error": {"code": "bad_request", "message": "rejected"},
        }

        normalized = protocol.validate_response(message)

        self.assertFalse(normalized["ok"])

    def test_response_result_and_error_shapes_are_validated(self) -> None:
        with self.assertRaisesRegex(protocol.ProtocolError, "result must be an object"):
            protocol.validate_response(
                {
                    "schema_version": protocol.PROTOCOL_SCHEMA_VERSION,
                    "request_id": "req-001",
                    "ok": True,
                    "result": "not-an-object",
                }
            )
        with self.assertRaisesRegex(protocol.ProtocolError, "code is not supported"):
            protocol.validate_response(
                {
                    "schema_version": protocol.PROTOCOL_SCHEMA_VERSION,
                    "request_id": "req-001",
                    "ok": False,
                    "error": {"code": "shell_failed", "message": "rejected"},
                }
            )

    def test_response_rejects_pathlike_result(self) -> None:
        message = {
            "schema_version": protocol.PROTOCOL_SCHEMA_VERSION,
            "request_id": "req-001",
            "ok": True,
            "result": {"kernel_path": "/dev/sda"},
        }

        with self.assertRaisesRegex(protocol.ProtocolError, "path-like"):
            protocol.validate_response(message)

    def test_all_methods_have_required_key_contracts(self) -> None:
        self.assertEqual(set(protocol.METHODS), set(protocol.METHOD_PARAM_KEYS))
        self.assertEqual(set(protocol.METHODS), set(protocol.METHOD_REQUIRED_KEYS))
        for method in protocol.METHODS:
            self.assertTrue(
                protocol.METHOD_REQUIRED_KEYS[method] <= protocol.METHOD_PARAM_KEYS[method], method
            )

    def test_all_method_requests_validate_with_exact_parameters(self) -> None:
        requests: dict[str, dict] = {
            "list_devices": {},
            "inspect_safety": {
                "source_id": SOURCE_ID,
                "observed_generation": GENERATION,
            },
            "prepare_read_only": {
                "source_id": SOURCE_ID,
                "observed_generation": GENERATION,
                "safety_inspection_id": opaque("safe"),
                "operator_confirmation_token": opaque("confirm"),
            },
            "launch_scanner": {
                "source_id": SOURCE_ID,
                "observed_generation": GENERATION,
                "safety_inspection_id": opaque("safe"),
                "readonly_preparation_id": opaque("roprep"),
                "scan_case_id": opaque("case"),
                "scratch_separation_id": opaque("scratch"),
                "resource_profile": "default",
            },
            "scanner_status": {"scanner_session_id": opaque("session")},
            "stop_scanner": {
                "scanner_session_id": opaque("session"),
                "reason": "operator stop",
            },
            "reconnect": {
                "scan_case_id": opaque("case"),
                "source_id": SOURCE_ID,
                "observed_generation": GENERATION,
            },
        }
        for method, params in requests.items():
            with self.subTest(method=method):
                normalized = protocol.validate_request(
                    request(method, params), source_generations={SOURCE_ID: GENERATION}
                )
                self.assertEqual(method, normalized["method"])

    def test_json_schema_parameter_contracts_match_python_validator(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        definitions = schema["$defs"]

        self.assertEqual(
            [{"$ref": "#/$defs/request"}, {"$ref": "#/$defs/response"}], schema["oneOf"]
        )
        for method in protocol.METHODS:
            params = definitions[f"{method}_params"]
            self.assertFalse(params["additionalProperties"], method)
            self.assertEqual(
                set(protocol.METHOD_PARAM_KEYS[method]), set(params["properties"]), method
            )
            self.assertEqual(
                set(protocol.METHOD_REQUIRED_KEYS[method]), set(params["required"]), method
            )
        self.assertEqual(
            set(protocol.ERROR_CODES), set(definitions["error"]["properties"]["code"]["enum"])
        )

    def test_launch_scanner_validates_without_container_surface(self) -> None:
        message = request(
            "launch_scanner",
            {
                "source_id": SOURCE_ID,
                "observed_generation": GENERATION,
                "safety_inspection_id": opaque("safe"),
                "readonly_preparation_id": opaque("roprep"),
                "scan_case_id": opaque("case"),
                "scratch_separation_id": opaque("scratch"),
                "resource_profile": "default",
            },
        )

        normalized = protocol.validate_request(message, source_generations={SOURCE_ID: GENERATION})

        self.assertEqual("launch_scanner", normalized["method"])
        self.assertNotIn("container_args", normalized["params"])

    def test_request_object_is_not_mutated(self) -> None:
        message = request("list_devices", {})
        original = copy.deepcopy(message)

        protocol.validate_request(message)

        self.assertEqual(original, message)


if __name__ == "__main__":
    unittest.main()
