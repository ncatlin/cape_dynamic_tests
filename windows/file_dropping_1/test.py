from cape_audit import CapeDynamicTestBase, CapeTestObjective, OSTarget
from cape_audit.verifiers import VerifyReportSectionHasMatching

class CapeDynamicTest (CapeDynamicTestBase):
    def __init__(self):
        super().__init__(test_name="file_dropping_1", analysis_package="exe")
        self.set_description("Tests 'Dropped File' detection. Creates files, directories and performs NTFS transactions.")
        self.set_payload_notes("A single statically linked 64-bit PE binary, tested on Windows 10.")
        self.set_result_notes("Most files should be detected as dropped. At the time of writing, files dropped by transactions (both committed and rolled back) are not fetched - though the API calls are correctly hooked.")
        self.set_zip_password(None)
        self.set_task_timeout_seconds(120)
        self.set_os_targets([OSTarget.WINDOWS])
        self.set_enforce_timeout(False)
        self.set_task_config({
              "Route": None,
              "Tags": [ "win10","x64"],
              "Request Options": "",
              "Custom Request Params": None
          })
        self._init_objectives()

    def _init_objectives(self):
        
        # First tests: simple file dropping
        # see if it picked up the first file as dropped
        o_dropfile_hook = CapeTestObjective(test=self, requirement="Detects a dropped file",
                                           objective_name="DetectFileDrop")
        o_dropfile_hook.set_success_msg("CAPE picked up a dropped file")
        o_dropfile_hook.set_failure_msg("There may be a hooking problem/change or the sample failed to run properly")
        evaluator = VerifyReportSectionHasMatching(
            path="dropped",
            match_criteria=[{"name":"FLAG_FILEDROP_1A_FLAG"}]
                )
        o_dropfile_hook.set_result_verifier(evaluator)
        self.add_objective(o_dropfile_hook)

        # now add a sub-objective to check its content
        o_dropfilecontent = CapeTestObjective(test=self,
                                              requirement="Retrieves content of a dropped file",  
                                              objective_name="GetFileDropContent")
        o_dropfilecontent.set_success_msg("CAPE read the correct content of a dropped file")
        o_dropfilecontent.set_failure_msg("There may be a hooking problem/change or the sample failed to run properly")
        evaluator = VerifyReportSectionHasMatching(
            path="dropped",
            match_criteria=[{"data":"FLAG_FILEDROP_1B_FLAG.*"}],
            values_are_regexes=True
            )
        o_dropfilecontent.set_result_verifier(evaluator)
        o_dropfile_hook.add_child_objective(o_dropfilecontent)

        # Next tests have some slight twists

        # for the next tests we mainly care about the content
        # so we will combine the flags
        o_immediate_delete = CapeTestObjective(test=self, requirement="Gets content of a file that is written then deleted",
                                              objective_name="GetImmediateDeleteFile")
        o_immediate_delete.set_success_msg("CAPE fetched a file that was deleted immediately after creation")
        o_immediate_delete.set_failure_msg("CAPE was unable to fetch a file that was written then immediately deleted")
        evaluator = VerifyReportSectionHasMatching(
            path="dropped",
            match_criteria=[
                {"data":"FLAG_FILEDROP_2A_FLAG"},
                {"data":"FLAG_FILEDROP_2B_FLAG.*"},
            ],
            values_are_regexes=True
            )
        o_immediate_delete.set_result_verifier(evaluator)
        o_dropfile_hook.add_child_objective(o_immediate_delete)

        o_never_close = CapeTestObjective(test=self, 
                                          requirement="Gets content of a file that is never closed",
                                         objective_name="GetNeverClosedFile")
        o_never_close.set_success_msg("CAPE fetched a file that did not have its handle closed")
        o_never_close.set_failure_msg("CAPE failed to fetch a file when its handle was left open")
        evaluator = VerifyReportSectionHasMatching(
            path="dropped",
            match_criteria=[
                {"data":"FLAG_FILEDROP_3A_FLAG"},
                {"data":"FLAG_FILEDROP_3B_FLAG.*"},
            ],
            values_are_regexes=True
            )
        o_never_close.set_result_verifier(evaluator)
        o_dropfile_hook.add_child_objective(o_never_close)

        ###
        # Directory-related tests
        ###
        o_dir_path = CapeTestObjective(test=self, 
                                       requirement="Handles directory creation",
                                       objective_name="GetDirfile")
        o_dir_path.set_success_msg("CAPE fetched a file from a newly created directory with the correct path")
        o_dir_path.set_failure_msg("CAPE had incorrect dropped file directory handling")
        evaluator = VerifyReportSectionHasMatching(
            path="dropped",
            match_criteria=[
                {"guest_paths":"FLAG_DIRDROP_1A_FLAG.*FLAG_DIRDROP_1B_FLAG"},
                {"data":"FLAG_DIRDROP_1C_FLAG"},
            ],
            values_are_regexes=True
            )
        o_dir_path.set_result_verifier(evaluator)
        self.add_objective(o_dir_path)


        o_dir_path_nest = CapeTestObjective(test=self,
                                       requirement="Handles nested directories", 
                                       objective_name="GetDirfileNested")
        o_dir_path_nest.set_success_msg("CAPE fetched a file from a newly created nested directory with the correct path")
        o_dir_path_nest.set_failure_msg("CAPE had incorrect nested dropped file directory handling")
        evaluator = VerifyReportSectionHasMatching(
            path="dropped",
            match_criteria=[
                {"guest_paths":"FLAG_DIRDROP_1A_FLAG.*FLAG_DIRDROP_1D_FLAG.*FLAG_DIRDROP_1E_FLAG"},
                {"data":"FLAG_DIRDROP_1F_FLAG"},
            ],
            values_are_regexes=True
            )
        o_dir_path_nest.set_result_verifier(evaluator)
        o_dir_path.add_child_objective(o_dir_path_nest)


        ###
        # NTFS transaction related tests
        ###
        o_committed_tx = CapeTestObjective(test=self,
                                       requirement="Fetches files dropped by committed NTFS transactions", 
                                      objective_name="CommittedTransaction")
        o_committed_tx.set_success_msg("CAPE fetched a file dropped by a committed transaction")
        o_committed_tx.set_failure_msg("CAPE did not fetch a file dropped by a committed transaction. (Known issue).")
        evaluator = VerifyReportSectionHasMatching(
            path="dropped",
            match_criteria=[
                {"name":"FLAG_TRANSACTION_1A_FLAG"},
                {"data":"FLAG_TRANSACTION_1B_FLAG.*"},
            ],
            values_are_regexes=True
            )
        o_committed_tx.set_result_verifier(evaluator)
        self.add_objective(o_committed_tx)

        
        o_transaction_api = CapeTestObjective(test=self, 
                                       requirement="Informational check for transaction API hooking", 
                                       objective_name="TransactionAPISupport", is_informational=True)
        o_transaction_api.set_success_msg("CAPE hooked transacted file creation.")
        o_transaction_api.set_failure_msg("CAPE did not hook transacted file creation.")
        evaluator = VerifyReportSectionHasMatching(
            path="behavior/processes/calls",
            match_criteria=[
                {"api": "CreateFileTransactedW"}, 
                {"arguments/value": ".*FLAG_TRANSACTION_1A_FLAG.*"} 
            ],
            values_are_regexes=True
            )
        o_transaction_api.set_result_verifier(evaluator)
        self.add_objective(o_transaction_api)

        o_reverted_tx = CapeTestObjective(test=self,
                                       requirement="Retrieves content of file written in reverted NTFS transactions", 
                                      objective_name="RevertedTransaction",
                                      is_informational=True)
        o_reverted_tx.set_success_msg("CAPE fetched a file dropped by a reverted transaction")
        o_reverted_tx.set_failure_msg("CAPE did not fetch a file created in a reverted transaction.")
        evaluator = VerifyReportSectionHasMatching(
            path="dropped",
            match_criteria=[
                {"name":"FLAG_TRANSACTION_2A_FLAG"},
                {"data":"FLAG_TRANSACTION_2B_FLAG.*"},
            ],
            values_are_regexes=True
            )
        o_reverted_tx.set_result_verifier(evaluator)
        self.add_objective(o_reverted_tx)



        o_transaction_api2 = CapeTestObjective(test=self, 
                                       requirement="Informational check for reverted transaction API hooking",  
                                       objective_name="TransactionAPISupport2", 
                                       is_informational=True)
        o_transaction_api2.set_success_msg("CAPE intercepted the API calls that created and reverted a file transaction.")
        o_transaction_api2.set_failure_msg("CAPE did not hook the API calls involved in reverted file transactions.")
        evaluator = VerifyReportSectionHasMatching(
            path="behavior/processes/calls",
            match_criteria=[
                {"category": "filesystem"}, 
                {"arguments/value": ".*FLAG_TRANSACTION_2A_FLAG.*"},
                {"arguments/value": ".*FLAG_TRANSACTION_2B_FLAG.*"}
            ],
            values_are_regexes=True
            )
        o_transaction_api2.set_result_verifier(evaluator)
        self.add_objective(o_transaction_api2)


if __name__ == "__main__":
    mytest = CapeDynamicTest()
    # developers: change me
    mytest.evaluate_results(r"[path_to_task_store_dir_after_payload_analysis]")
    mytest.print_test_results()
