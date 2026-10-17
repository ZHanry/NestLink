"""Pure package-owner migration/admission policy, with every system call mocked."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[2]
INSTANCE="147eb612-b6c7-4a75-ae12-a91fe7df36fd"


@unittest.skipUnless(sys.platform=="linux","Linux lifecycle uses fcntl")
class SchemaMigrationPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec=importlib.util.spec_from_file_location("nestlink_schema_migration_lifecycle",ROOT/"packaging/linux/lifecycle.py")
        cls.lifecycle=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.lifecycle)

    def fixture(self):
        previous={"id":"linux-x64-server","manifest_sha256":"a"*64,"package_sha256":"b"*64,"update_certificate_sha256":"c"*64,"version":"15.0.0","sequence":1,"source_revision":"d"*40,"state_compatibility":"v15-control-schema18-epoch1"}
        incoming=dict(previous,version="15.0.1",sequence=2,state_compatibility="v15-control-schema19-epoch1",manifest_sha256="e"*64,package_sha256="f"*64)
        record={"schema_version":1,"role":"server","current":previous,"previous":None,"maximum_sequence":1,"maximum_accepted":previous,"instance":{"schema_version":1,"namespace":"NestLink-v15","instance_id":INSTANCE,"active":True}}
        config=Path("/var/lib/nestlink-v15/instances")/INSTANCE/"server.toml"
        args=SimpleNamespace(role="server",recover_incomplete=False,action="install",bundle=Path("/mutable"),manifest=Path("manifest"),signature=Path("sig"),certificate=Path("cert"),certificate_sha256="c"*64,artifact_id=previous["id"],migrate_config=config,migration_backup=Path("/private/backups/new.nl15"),migration_password_file=Path("/private/password"))
        data={"purpose":"native-packages","version":"15.0.1","release_sequence":2,"source_revision":"d"*40}
        item={"state_compatibility":incoming["state_compatibility"]}
        receipt={"schema_version":1,"transaction_id":INSTANCE,"deployment_id":"292b8868-d739-4273-a556-65b7fe82c32c","from_schema":18,"to_schema":19,"archive_sha256":"a"*64,"old_snapshot_sha256":"b"*64,"new_snapshot_sha256":"c"*64,"previous_directory":"retained-fixture"}
        return previous,incoming,record,args,data,item,receipt

    def test_supported_forward_plan_requires_active_config_and_private_external_backup_inputs(self):
        previous,incoming,record,args,*_=self.fixture()
        self.assertEqual(self.lifecycle.plan_upgrade(args,previous,incoming,record)["to_schema"],19)
        self.assertIsNone(self.lifecycle.plan_upgrade(args,previous,previous,record))
        for attribute,value in (("migrate_config",None),("migrate_config",Path("/old/control/server.toml")),("migration_backup",args.migrate_config.parent/"inside.nl15"),("migration_password_file",Path("relative")),("role","desktop")):
            changed=copy.copy(args);setattr(changed,attribute,value)
            with self.subTest(attribute=attribute,value=value),self.assertRaises(ValueError):self.lifecycle.plan_upgrade(changed,previous,incoming,record)
        for state in ("v15-control-schema17-epoch1","v15-control-schema19-epoch2","other-unknown-state"):
            changed=dict(incoming,state_compatibility=state)
            with self.subTest(state=state),self.assertRaises(ValueError):self.lifecycle.plan_upgrade(args,previous,changed,record)

    def test_explicit_incomplete_resume_allows_only_exact_latest_current_receipt(self):
        previous,_,record,*_=self.fixture()
        with self.assertRaises(ValueError):self.lifecycle.accepted_update(record,previous)
        self.lifecycle.accepted_update(record,previous,recover=True)
        changed=dict(previous,package_sha256="f"*64)
        with self.assertRaises(ValueError):self.lifecycle.accepted_update(record,changed,recover=True)

    def execute(self, *, activation_failure=False, finalization_failure=False, migration_failure=False):
        previous,incoming,record,args,data,item,receipt=self.fixture()
        owner=SimpleNamespace(root=Path("/owned-fixture/install"),owner="a"*32,was_incomplete=False,finish=mock.Mock())
        transaction=mock.MagicMock();transaction.__enter__.return_value=owner
        commands=[]
        def server(executable,command,*arguments):
            commands.append((command,arguments))
            if command=="schema":return json.dumps({"schema_version":1,"schema":18}).encode()
            if command=="migrate":
                if migration_failure:raise ValueError("owned fixture process interrupted before receipt")
                self.assertIn("--defer-admission",arguments)
                return json.dumps(receipt).encode()
            if command=="recover-migration" and "--complete" in arguments and finalization_failure:raise ValueError("owned fixture finalization uncertainty")
            return json.dumps(receipt).encode()
        lifecycle=self.lifecycle
        patches={"Transaction":mock.Mock(return_value=transaction),"read_receipt":mock.Mock(return_value=record),"recover_instance":mock.Mock(),"installed_processes":mock.Mock(return_value=[]),"release_record":mock.Mock(return_value=incoming),"cache_release":mock.Mock(return_value=incoming),"select_cached":mock.Mock(return_value=(data,item,Path("/private-cache/fixed.deb"))),"package_metadata":mock.Mock(),"verify_installed_payload":mock.Mock(),"activate":mock.Mock(side_effect=OSError("owned activation failure") if activation_failure else None),"commit_instance":mock.Mock(),"server_command":mock.Mock(side_effect=server),"run":mock.Mock(return_value=b"")}
        with mock.patch.multiple(lifecycle,**patches),mock.patch.object(lifecycle.verify,"verify_selected",return_value=(data,item,Path("/mutable/untrusted.deb"))),mock.patch.object(lifecycle.subprocess,"run",return_value=SimpleNamespace(returncode=1)):
            if any((activation_failure,finalization_failure,migration_failure)):
                with self.assertRaises((OSError,ValueError)):lifecycle.lifecycle(args)
            else:lifecycle.lifecycle(args)
        return owner,commands,patches

    def test_success_defers_schema_admission_until_package_receipt_then_finalizes(self):
        owner,commands,patches=self.execute()
        self.assertEqual([value[0] for value in commands],["schema","migrate","recover-migration"])
        self.assertIn("--complete",commands[-1][1])
        patches["commit_instance"].assert_called_once();owner.finish.assert_called_once()

    def test_failure_before_admission_rolls_schema_back_before_old_package_restore(self):
        owner,commands,patches=self.execute(activation_failure=True)
        self.assertIn("--rollback",commands[-1][1])
        self.assertTrue(any(call.args[0][0]=="dpkg" for call in patches["run"].call_args_list))
        owner.finish.assert_not_called()

    def test_uncertain_finalization_never_replays_old_schema_or_downgrades_migrator(self):
        for options in ({"finalization_failure":True},{"migration_failure":True}):
            with self.subTest(options=options):
                owner,commands,patches=self.execute(**options)
                self.assertFalse(any("--rollback" in arguments for _,arguments in commands))
                self.assertFalse(any(call.args[0][0]=="dpkg" for call in patches["run"].call_args_list))
                owner.finish.assert_not_called()


if __name__=="__main__":unittest.main()
