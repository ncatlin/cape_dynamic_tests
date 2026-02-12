from cape_audit import CapeDynamicTestBase, CapeTestObjective, OSTarget
from cape_audit.verifiers import (VerifyReportSectionHasMatching, 
                       VerifyReportSectionHasContent,
                       VerifyReportHasPattern, 
                       VerifyReportHasExactString)

import re

class CapeDynamicTest(CapeDynamicTestBase):
    def __init__(self):
        super().__init__(test_name="api_tracing_1", analysis_package="exe")
        self.set_description("Tests API monitoring. " \
            "Runs a series of Windows API calls including file, registry, network and synchronisation.")
        self.set_payload_notes("A single statically linked 64-bit PE binary, tested on Windows 10.")
        self.set_result_notes("These simple hooking tests are all expected to succeed on a correct CAPE setup")
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

        # check if there are any behavioural listings at all in the report
        o_has_behaviour_trace = CapeTestObjective(test=self, 
                                                  requirement="API calls are being hooked", 
                                                  objective_name="BehaviourInfoGenerated")
        o_has_behaviour_trace.set_success_msg("API hooking is working")
        o_has_behaviour_trace.set_failure_msg("The sample failed to execute, the monitor failed\
                                         to initialise or API hooking is not working")
        o_has_behaviour_trace.set_result_verifier(VerifyReportSectionHasContent("behavior"))
        self.add_objective(o_has_behaviour_trace)

        # check if it caught the sleep with a specific argument
        o_sleep_hook = CapeTestObjective(test=self, 
                                         requirement="A sleep call is hooked, including its parameter",
                                        objective_name="DetectSleepTime", 
                                        is_informational=False)
        o_sleep_hook.set_success_msg("CAPE hooked a sleep and retrieved the correct argument")
        o_sleep_hook.set_failure_msg("There may be a hooking problem/change or the sample failed to run properly")
        evaluator = VerifyReportSectionHasMatching(
            path="behavior/processes/calls",
            match_criteria=[
                {"api": "NtDelayExecution"}, 
                {"arguments/value": "1337"}
            ])
        o_sleep_hook.set_result_verifier(evaluator)
        o_has_behaviour_trace.add_child_objective(o_sleep_hook)

        # check if I/O content is retrieved
        o_console_write = CapeTestObjective(test=self, 
                                            requirement="I/O APIs are hooked",
                                           objective_name="DetectConsoleWrite", is_informational=False)
        o_console_write.set_success_msg("CAPE hooked a file write")
        o_console_write.set_failure_msg("There may be a hooking problem/change or the sample failed to run properly")
        o_console_write.set_result_verifier(VerifyReportHasPattern(pattern=re.compile("FLAG_WRITECONSOLE_FLAG")))
        o_has_behaviour_trace.add_child_objective(o_console_write)


        # check if the name passed to a file creation API is retrieved
        o_mem_copy = CapeTestObjective(test=self, 
                                            requirement="Buffer writes are hooked",
                                            objective_name="DetectMemoryCopy", is_informational=False)
        o_mem_copy.set_success_msg("CAPE hooked a memory buffer copy")
        o_mem_copy.set_failure_msg("There may be a hooking problem/change or the sample failed to run properly")
        o_mem_copy.set_result_verifier(VerifyReportHasExactString("FLAG_MEMCPY_FLAG"))
        o_has_behaviour_trace.add_child_objective(o_mem_copy)


        o_file_create = CapeTestObjective(test=self, 
                                            requirement="File creation APIs are hooked",
                                            objective_name="FileCreationDetection")
        o_file_create.set_success_msg("CAPE hooked file creation")
        o_file_create.set_failure_msg("There may be a hooking problem/change or the sample failed to run properly")
        evaluator = VerifyReportSectionHasMatching(
            path="behavior/processes/calls",
            match_criteria=[
                {"api": "NtCreateFile"},
                {"arguments/value": r".*FLAG_CREATED_FILENAME_FLAG.txt.*"}
            ],
            values_are_regexes=True
            )
        o_file_create.set_result_verifier(evaluator)
        o_has_behaviour_trace.add_child_objective(o_file_create)


        o_regcreate_hook = CapeTestObjective(test=self, 
                                            requirement="Registry key creation is hooked",
                                            objective_name="HookRegCreateKey", is_informational=False)
        o_regcreate_hook.set_success_msg("CAPE hooked RegCreateKeyExA retrieved the correct argument")
        o_regcreate_hook.set_failure_msg("There may be a hooking problem/change or the sample failed to run properly")
        evaluator = VerifyReportSectionHasMatching(
            path="behavior/processes/calls",
            match_criteria=[
                {"api": "RegCreateKeyExA"}, 
                {"arguments/value": "Software\\FLAG_REGISTRY_KEY_NAME_FLAG"}
            ])
        o_regcreate_hook.set_result_verifier(evaluator)
        o_has_behaviour_trace.add_child_objective(o_regcreate_hook)

        # this objective looks for multiple flags passed to the same API call at once
        # we add it as a child of o_regcreate_hook, because if creating the key didn't work
        # then setting the value won't either
        o_regset_hook = CapeTestObjective(test=self, 
                                          requirement="Registry key writes are hooked", 
                                          objective_name="HookRegSetVal", 
                                          is_informational=False)
        o_regset_hook.set_success_msg("CAPE hooked RegSetValueExA and retrieved the content it was setting")
        o_regset_hook.set_failure_msg("There may be a hooking problem/change or the sample failed to run properly")
        evaluator = VerifyReportSectionHasMatching(
            path="behavior/processes/calls",
            match_criteria=[
                {"api": "RegSetValueExA"}, 
                {"arguments/value": "FLAG_REGISTRY_VALUE_NAME_FLAG"},
                {"arguments/value": "FLAG_REGISTRY_VALUE_CONTENT_FLAG"}
            ])
        o_regset_hook.set_result_verifier(evaluator)
        o_regcreate_hook.add_child_objective(o_regset_hook)

        o_net_send_hook = CapeTestObjective(test=self, 
                                            requirement="Data sent via network APIs is hooked", 
                                            objective_name="HookNetSend", is_informational=False)
        o_net_send_hook.set_success_msg("CAPE hooked windsock::send and retrieved the data sent")
        o_net_send_hook.set_failure_msg("There may be a hooking problem/change or the sample failed to run properly")
        evaluator = VerifyReportSectionHasMatching(
            path="behavior/processes/calls",
            match_criteria=[
                {"api": "send"}, 
                {"arguments/value": "FLAG_NETWORK_SENT_DATA_FLAG"}
            ])
        o_net_send_hook.set_result_verifier(evaluator)
        o_has_behaviour_trace.add_child_objective(o_net_send_hook)


        o_mutex_hook = CapeTestObjective(test=self, 
                                            requirement="Synchronisation APIs are hooked",
                                         objective_name="HookCreateMutex", is_informational=False)
        o_mutex_hook.set_success_msg("CAPE hooked Mutex creation and retrieved the name")
        o_mutex_hook.set_failure_msg("There may be a hooking problem/change or the sample failed to run properly")
        evaluator = VerifyReportSectionHasMatching(
            path="behavior/processes/calls",
            match_criteria=[
                {"api": "NtCreateMutant"}, 
                {"arguments/value": "FLAG_MUTEX_NAME_FLAG"}
            ])
        o_mutex_hook.set_result_verifier(evaluator)
        o_has_behaviour_trace.add_child_objective(o_mutex_hook)


        # instead of searching for flags passed to specific API names,
        # we can widen the search to API categories
        o_key_hook = CapeTestObjective(test=self, 
                                       requirement="Crypto API parameters are recorded",
                                       objective_name="HookCryptFlag", is_informational=False)
        o_key_hook.set_success_msg("CAPE hooked a crypto API and retrieved the argument")
        o_key_hook.set_failure_msg("There may be a hooking problem/change or the sample failed to run properly")
        evaluator = VerifyReportSectionHasMatching(
            path="behavior/processes/calls",
            match_criteria=[
                {"category": "crypto"}, 
                {"arguments/value": "FLAG_CRYPT_KEY_FLAG"}
            ])
        o_key_hook.set_result_verifier(evaluator)
        o_has_behaviour_trace.add_child_objective(o_key_hook)

        # Searching for exact flags can be risky - this one appears in the report with 
        # a null terminator. Using a regex finds it though.
        # Doing a string search VerifyReportHasPattern/VerifyReportHasExactString would also work
        o_mutex_hook = CapeTestObjective(test=self, 
                                            requirement="Crypto API buffers are intercepted",
                                         objective_name="HookCryptData", is_informational=False)
        o_mutex_hook.set_success_msg("CAPE retrieved the data passed to a crypto operation")
        o_mutex_hook.set_failure_msg("There may be a hooking problem/change or the sample failed to run properly")
        evaluator = VerifyReportSectionHasMatching(
            path="behavior/processes/calls",
            match_criteria=[
                {"category": "crypto"}, 
                {"arguments/value": "FLAG_CRYPT_PLAINTEXT_FLAG.*"}
            ],
            values_are_regexes=True)
        o_mutex_hook.set_result_verifier(evaluator)
        o_key_hook.add_child_objective(o_mutex_hook)


if __name__ == "__main__":
    mytest = CapeDynamicTest()
    # developers: change me
    mytest.evaluate_results(r"[path_to_task_store_dir_after_payload_analysis]")
    mytest.print_test_results()
