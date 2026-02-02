from typing import Any, Dict, List, Optional, Union
from cape_test.cape_test import CapeDynamicTestBase, CapeTestObjective
from cape_test.verifiers import VerifyReportSectionHasMatching, VerifyReportSectionHasContent, VerifyReportHasPattern, VerifyReportHasExactString
import cape_test
import os
import re
import json

class CapeDynamicTest (CapeDynamicTestBase):
    def __init__(self):
        self.metadata = {}
        self._init_metadata()
        self.objectives = []
        self._init_objectives()

    def _init_metadata(self):
        self.metadata =  {
          "Name": "file_dropping_1",
          "Description": "Tests 'Dropped File' detection. Creates files, directories and performs NTFS transactions.",
          "Payload Notes": "A single statically linked 64-bit PE binary, tested on Windows 10.",
          "Result Notes": "Most files should be detected as dropped. At the time of writing, files dropped by transactions (both committed and rolled back) are not fetched - though the API calls are correctly hooked.",
          "Zip Password": None,
          "Timeout": 120,
          "Targets": [ "windows" ],
          "Package": "exe",
          "Task Config":{
              "Timeout": 120,
              "Route": None,
              "Tags": [ "windows", "exe" ],
              "Request Options": None,
              "Custom Request Params": None,
              "Dump Interesting Buffers": False,
              "Dump Process Memory": False,
              "Trace Syscalls": True,
              "Old Thread Based Loader": False,
              "Unpacker": False,
              "Unmonitored": False,
              "Enforce Timeout": False,
              "AMSI Dumping By Monitor": False,
              "Import Reconstruction": False
          }
        }
        
    def get_metadata(self):
        return self.metadata

    def _init_objectives(self):
        
        # First tests: simple file dropping
        # see if it picked up the first file as dropped
        o_dropfile_hook = CapeTestObjective(test=self, objective_name="DetectFileDrop")
        o_dropfile_hook.set_success_msg("CAPE picked up a dropped file")
        o_dropfile_hook.set_failure_msg("There may be a hooking problem/change or the sample failed to run properly")
        evaluator = VerifyReportSectionHasMatching(
            path="dropped",
            match_criteria={"name":"FLAG_FILEDROP_1A_FLAG"}
                )
        o_dropfile_hook.set_result_verifier(evaluator)
        self.add_objective(o_dropfile_hook)

        # now add a sub-objective to check its content
        o_dropfilecontent = CapeTestObjective(test=self, objective_name="GetFileDropContent")
        o_dropfilecontent.set_success_msg("CAPE read the correct content of a dropped file")
        o_dropfilecontent.set_failure_msg("There may be a hooking problem/change or the sample failed to run properly")
        evaluator = VerifyReportSectionHasMatching(
            path="dropped",
            match_criteria={"data":"FLAG_FILEDROP_1B_FLAG.*"},
            values_are_regexes=True
            )
        o_dropfilecontent.set_result_verifier(evaluator)
        o_dropfile_hook.add_child_objective(o_dropfilecontent)

        # Next tests have some slight twists

        # for the next tests we mainly care about the content
        # so we will combine the flags
        o_immediate_delete = CapeTestObjective(test=self, objective_name="GetImmediateDeleteFile")
        o_immediate_delete.set_success_msg("CAPE fetched a file that was deleted immediately after creation")
        o_immediate_delete.set_failure_msg("CAPE was unable to fetch a file that was written then immediately deleted")
        evaluator = VerifyReportSectionHasMatching(
            path="dropped",
            match_criteria={
                "data":"FLAG_FILEDROP_2A_FLAG",
                "data":"FLAG_FILEDROP_2B_FLAG.*",
                },
            values_are_regexes=True
            )
        o_immediate_delete.set_result_verifier(evaluator)
        self.add_objective(o_immediate_delete)

        o_never_close = CapeTestObjective(test=self, objective_name="GetImmediateNeverClose")
        o_never_close.set_success_msg("CAPE fetched a file that did not have its handle closed")
        o_never_close.set_failure_msg("CAPE failed to fetch a file when its handle was left open")
        evaluator = VerifyReportSectionHasMatching(
            path="dropped",
            match_criteria={
                "data":"FLAG_FILEDROP_3A_FLAG",
                "data":"FLAG_FILEDROP_3B_FLAG.*",
                },
            values_are_regexes=True
            )
        o_never_close.set_result_verifier(evaluator)
        self.add_objective(o_never_close)

        # Directory-related tests

        o_dir_path = CapeTestObjective(test=self, objective_name="GetDirfile")
        o_dir_path.set_success_msg("CAPE fetched a file from a newly created directory with the correct path")
        o_dir_path.set_failure_msg("CAPE had incorrect dropped file directory handling")
        evaluator = VerifyReportSectionHasMatching(
            path="dropped",
            match_criteria={
                "guest_paths":"FLAG_DIRDROP_1A_FLAG.*FLAG_DIRDROP_1B_FLAG",
                "data":"FLAG_DIRDROP_1C_FLAG",
                },
            values_are_regexes=True
            )
        o_dir_path.set_result_verifier(evaluator)
        self.add_objective(o_dir_path)


        o_dir_path_nest = CapeTestObjective(test=self, objective_name="GetDirfileNested")
        o_dir_path_nest.set_success_msg("CAPE fetched a file from a newly created nested directory with the correct path")
        o_dir_path_nest.set_failure_msg("CAPE had incorrect nested dropped file directory handling")
        evaluator = VerifyReportSectionHasMatching(
            path="dropped",
            match_criteria={
                "guest_paths":"FLAG_DIRDROP_1A_FLAG.*FLAG_DIRDROP_1D_FLAG.*FLAG_DIRDROP_1E_FLAG",
                "data":"FLAG_DIRDROP_1F_FLAG",
                },
            values_are_regexes=True
            )
        o_dir_path_nest.set_result_verifier(evaluator)
        self.add_objective(o_dir_path_nest)



        # NTFS transaction related tests
        o_committed_tx = CapeTestObjective(test=self, objective_name="CommittedTransaction")
        o_committed_tx.set_success_msg("CAPE fetched a file dropped by a committed transaction")
        o_committed_tx.set_failure_msg("CAPE did not fetch a file dropped by a committed transaction. (Known issue).")
        evaluator = VerifyReportSectionHasMatching(
            path="dropped",
            match_criteria={
                "name":"FLAG_TRANSACTION_1A_FLAG",
                "data":"FLAG_TRANSACTION_1B_FLAG.*",
                },
            values_are_regexes=True
            )
        o_committed_tx.set_result_verifier(evaluator)
        self.add_objective(o_committed_tx)

        
        o_transaction_api = CapeTestObjective(test=self, objective_name="TransactionAPISupport", is_informational=True)
        o_transaction_api.set_success_msg("CAPE hooked transacted file creation.")
        o_transaction_api.set_failure_msg("CAPE did not hook transacted file creation.")
        evaluator = VerifyReportSectionHasMatching(
            path="behavior/processes/calls",
            match_criteria={
                "api": "CreateFileTransactedW", 
                "arguments/value": ".*FLAG_TRANSACTION_1A_FLAG.*"
            },
            values_are_regexes=True
            )
        o_transaction_api.set_result_verifier(evaluator)
        self.add_objective(o_transaction_api)

        o_reverted_tx = CapeTestObjective(test=self, objective_name="RevertedTransaction")
        o_reverted_tx.set_success_msg("CAPE fetched a file dropped by a reverted transaction")
        o_reverted_tx.set_failure_msg("CAPE did not fetch a file dropped by a reverted transaction. (Possibly intended behaviour).")
        evaluator = VerifyReportSectionHasMatching(
            path="dropped",
            match_criteria={
                "name":"FLAG_TRANSACTION_2A_FLAG",
                "data":"FLAG_TRANSACTION_2B_FLAG.*",
                },
            values_are_regexes=True
            )
        o_reverted_tx.set_result_verifier(evaluator)
        self.add_objective(o_reverted_tx)



        o_transaction_api2 = CapeTestObjective(test=self, objective_name="TransactionAPISupport2", is_informational=True)
        o_transaction_api2.set_success_msg("CAPE intercepted the data written to a revered transacted file.")
        o_transaction_api2.set_failure_msg("CAPE did not hook a transacted file write.")
        evaluator = VerifyReportSectionHasMatching(
            path="behavior/processes/calls",
            match_criteria={
                "category": "filesystem", 
                "arguments/value": ".*FLAG_TRANSACTION_2A_FLAG.*",
                "arguments/value": ".*FLAG_TRANSACTION_2B_FLAG.*"
            },
            values_are_regexes=True
            )
        o_transaction_api2.set_result_verifier(evaluator)
        self.add_objective(o_transaction_api2)




mytest = CapeDynamicTest()
mytest.evaluate_results(r"C:\Users\niaca\OneDrive\Documents\test_storedir")
mytest.print_test_results()
