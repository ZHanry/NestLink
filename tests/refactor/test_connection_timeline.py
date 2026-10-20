import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("connection_timeline", Path(__file__).parents[2] / "scripts/refactor-connection-timeline.py")
timeline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(timeline)


class ConnectionTimelineTests(unittest.TestCase):
    def setUp(self):
        self.request, self.local, self.remote = "a" * 64, "b" * 64, "c" * 64
        self.signal = dict(network_generation=1, sequence=2, description_sequence=1, lease_sequence=1)
        self.trace = dict(request_sha256=self.request, connection_generation=9,
                          local_device_sha256=self.local, remote_device_sha256=self.remote,
                          events=[dict(elapsed_ms=100, stage="signal_submitted", signal=self.signal),
                                  dict(elapsed_ms=150, stage="remote_description_set"),
                                  dict(elapsed_ms=180, stage="path_verified")])
        self.host = [dict(request_sha256=self.request, connection_generation=9,
                         peer_timeline=dict(local_device_sha256=self.remote, remote_device_sha256=self.local,
                                            last_remote_signal=self.signal, started_unix_ms=99999999,
                                            offer_received_ms=5))]
        self.server = [dict(event="connection_timeline", request_sha256=self.request, connection_generation=9,
                           sender_device_sha256=self.local, stage="SignalAccepted", unix_ms=1, **self.signal)]

    def test_exact_identity_and_sequences_join_even_with_unsynchronized_clocks(self):
        report = timeline.correlate(self.trace, self.host, self.server)
        self.assertTrue(report["signals"][0]["recipient_consumption_observed"])
        self.assertFalse(report["signals"][0]["accepted_without_consumption_observation"])
        self.assertEqual(report["controller_local_durations_ms"]["offer_to_verified_path"], 80)
        self.assertFalse(report["cross_clock_latencies_computed"])

    def test_later_revision_does_not_claim_consumption_of_an_earlier_signal(self):
        self.host[0]["peer_timeline"]["last_remote_signal"] = dict(self.signal, sequence=3)
        report = timeline.correlate(self.trace, self.host, self.server)
        self.assertTrue(report["signals"][0]["accepted_without_consumption_observation"])
        self.assertFalse(report["signals"][0]["recipient_consumption_observed"])

    def test_other_generation_and_request_do_not_leak_into_report(self):
        self.host[0]["connection_generation"] = 8
        self.server[0]["request_sha256"] = "d" * 64
        report = timeline.correlate(self.trace, self.host, self.server)
        self.assertEqual((report["matched_host_records"], report["matched_server_records"]), (0, 0))

    def test_free_form_input_and_credentials_are_never_copied(self):
        self.trace["sdp"] = "private-password-192.0.2.1"
        self.server[0]["message"] = "private-password-192.0.2.1"
        self.assertNotIn("private-password", json.dumps(timeline.correlate(self.trace, self.host, self.server)))

    def test_wrong_endpoint_clock_regression_and_malformed_sequences_are_rejected(self):
        self.host[0]["peer_timeline"]["local_device_sha256"] = "d" * 64
        with self.assertRaises(ValueError):
            timeline.correlate(self.trace, self.host, self.server)
        self.trace["events"][1]["elapsed_ms"] = 1
        with self.assertRaises(ValueError):
            timeline.correlate(self.trace, [], [])
        self.trace["events"][1]["elapsed_ms"] = 150
        self.signal["sequence"] = True
        with self.assertRaises(ValueError):
            timeline.correlate(self.trace, [], [])

    def test_malformed_record_shapes_and_observation_budgets_are_rejected(self):
        for controller, host, server in [(None, [], []), ({"controller_timeline": []}, [], []),
                                          (self.trace, [None], []), (self.trace, [], [None]),
                                          (self.trace, [], [{"fields": []}])]:
            with self.subTest(controller=controller, host=host, server=server):
                with self.assertRaises(ValueError):
                    timeline.correlate(controller, host, server)
        self.trace["events"] *= 44
        with self.assertRaises(ValueError):
            timeline.correlate(self.trace, [], [])

    def test_prepermit_failure_is_reportable_without_a_peer_or_invented_generation(self):
        failure = dict(elapsed_ms=20, stage='request_started', failure='identity_storage_unavailable',
                       message='private-password')
        preflight = dict(request_sha256=self.request, connection_generation=0, local_device_sha256=None,
                         remote_device_sha256=self.remote, first_failure=failure, events=[failure])
        report = timeline.correlate({'controller_timeline': None, 'controller_preflight_timeline': preflight}, [], [])
        self.assertFalse(report['peer_observations_available'])
        self.assertEqual(report['connection_generation'], 0)
        self.assertEqual(report['controller_preflight']['first_failure']['failure'], 'identity_storage_unavailable')
        self.assertNotIn('private-password', json.dumps(report))
        failure['failure'] = 'private-password'
        with self.assertRaises(ValueError):
            timeline.correlate({'controller_timeline': None, 'controller_preflight_timeline': preflight}, [], [])

    def test_preflight_and_peer_cannot_mix_request_generation_or_endpoint_bindings(self):
        preflight = dict(self.trace, events=[dict(stage='permit_received', elapsed_ms=1)])
        controller = dict(controller_timeline=self.trace, controller_preflight_timeline=preflight)
        self.assertTrue(timeline.correlate(controller, [], [])['peer_observations_available'])
        for key, value in [('request_sha256', 'd' * 64), ('connection_generation', 8),
                           ('local_device_sha256', self.remote), ('remote_device_sha256', self.local)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                timeline.correlate(dict(controller, controller_preflight_timeline=dict(preflight, **{key: value})), [], [])

    def test_first_failure_survives_ring_eviction_but_free_form_labels_are_rejected(self):
        self.trace['first_failure'] = dict(elapsed_ms=1, stage='peer_created', failure='startup_authorization_expired')
        report = timeline.correlate(self.trace, [], [])
        self.assertEqual(report['controller_first_failure']['failure'], 'startup_authorization_expired')
        self.trace['first_failure']['failure'] = 'private-error-text'
        with self.assertRaises(ValueError):
            timeline.correlate(self.trace, [], [])


if __name__ == "__main__":
    unittest.main()
