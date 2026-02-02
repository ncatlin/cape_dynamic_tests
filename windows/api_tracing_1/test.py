from typing import Any, Dict, List, Optional, Union
from cape_test.cape_test import CapeDynamicTestBase, CapeTestObjective, OSTarget
from cape_test.verifiers import (VerifyReportSectionHasMatching, 
                                 VerifyReportSectionHasContent,
                                   VerifyReportHasPattern, 
                                   VerifyReportHasExactString)
import re

    
class CapeDynamicTest(CapeDynamicTestBase):
    def __init__(self, test_name, analysis_package):
        super().__init__(test_name, analysis_package)
        self.set_description("Tests API monitoring. " \
        "Runs a series of Windows API calls including file, registry, network and synchronisation.")
        self.set_payload_notes("A single statically linked 64-bit PE binary, tested on Windows 10.")
        self.set_result_notes("These simple hooking tests are all expected to succeed on a correct CAPE setup")
        self.set_zip_password(None)
        self.set_task_timeout_seconds(120)
        self.set_os_targets([OSTarget.WINDOWS])
        self.set_task_config({
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
          })
        self._init_objectives()

    def _init_objectives(self):

        # check if there are any behavioural listings at all in the report
        o_has_behaviour_trace = CapeTestObjective(test=self, objective_name="BehaviourInfoGenerated")
        o_has_behaviour_trace.set_success_msg("API hooking is working")
        o_has_behaviour_trace.set_failure_msg("The sample failed to execute, the monitor failed\
                                         to initialise or API hooking is not working")
        o_has_behaviour_trace.set_result_verifier(VerifyReportSectionHasContent("behavior"))
        self.add_objective(o_has_behaviour_trace)

        # check if it caught the sleep with a specific argument
        o_sleep_hook = CapeTestObjective(test=self, objective_name="DetectSleepTime", is_informational=False)
        o_sleep_hook.set_success_msg("CAPE hooked a sleep and retrieved the correct argument")
        o_sleep_hook.set_failure_msg("There may be a hooking problem/change or the sample failed to run properly")
        evaluator = VerifyReportSectionHasMatching(
            path="behavior/processes/calls",
            match_criteria={
                "api": "NtDelayExecution", 
                "arguments/value": "1337"
            })
        o_sleep_hook.set_result_verifier(evaluator)
        o_has_behaviour_trace.add_child_objective(o_sleep_hook)

        # check if I/O content is retrieved
        o_console_write = CapeTestObjective(test=self, objective_name="DetectConsoleWrite", is_informational=False)
        o_console_write.set_success_msg("CAPE hooked a file write")
        o_console_write.set_failure_msg("There may be a hooking problem/change or the sample failed to run properly")
        o_console_write.set_result_verifier(VerifyReportHasPattern(pattern=re.compile("FLAG_WRITECONSOLE_FLAG")))
        o_has_behaviour_trace.add_child_objective(o_console_write)


        # check if the name passed to a file creation API is retrieved
        o_mem_copy = CapeTestObjective(test=self, objective_name="DetectMemoryCopy", is_informational=False)
        o_mem_copy.set_success_msg("CAPE hooked a memory buffer copy")
        o_mem_copy.set_failure_msg("There may be a hooking problem/change or the sample failed to run properly")
        o_mem_copy.set_result_verifier(VerifyReportHasExactString("FLAG_MEMCPY_FLAG"))
        o_has_behaviour_trace.add_child_objective(o_mem_copy)


        o_file_create = CapeTestObjective(test=self, objective_name="FileCreationDetection")
        o_file_create.set_success_msg("CAPE hooked file creation")
        o_file_create.set_failure_msg("There may be a hooking problem/change or the sample failed to run properly")
        evaluator = VerifyReportSectionHasMatching(
            path="behavior/processes/calls",
            match_criteria={
                "api": "NtCreateFile",
                "arguments/value": r".*FLAG_CREATED_FILENAME_FLAG.txt.*"
            },
            values_are_regexes=True
            )
        o_file_create.set_result_verifier(evaluator)
        o_has_behaviour_trace.add_child_objective(o_file_create)


        o_regcreate_hook = CapeTestObjective(test=self, objective_name="HookRegCreateKey", is_informational=False)
        o_regcreate_hook.set_success_msg("CAPE hooked RegCreateKeyExA retrieved the correct argument")
        o_regcreate_hook.set_failure_msg("There may be a hooking problem/change or the sample failed to run properly")
        evaluator = VerifyReportSectionHasMatching(
            path="behavior/processes/calls",
            match_criteria={
                "api": "RegCreateKeyExA", 
                "arguments/value": "Software\\FLAG_REGISTRY_KEY_NAME_FLAG"
            })
        o_regcreate_hook.set_result_verifier(evaluator)
        o_has_behaviour_trace.add_child_objective(o_regcreate_hook)

        # this objective looks for multiple flags passed to the same API call at once
        # we add it as a child of o_regcreate_hook, because if creating the key didn't work
        # then setting the value won't either
        o_regset_hook = CapeTestObjective(test=self, objective_name="HookRegSetVal", is_informational=False)
        o_regset_hook.set_success_msg("CAPE hooked RegSetValueExA and retrieved the content it was setting")
        o_regset_hook.set_failure_msg("There may be a hooking problem/change or the sample failed to run properly")
        evaluator = VerifyReportSectionHasMatching(
            path="behavior/processes/calls",
            match_criteria={
                "api": "RegSetValueExA", 
                "arguments/value": "FLAG_REGISTRY_VALUE_NAME_FLAG",
                "arguments/value": "FLAG_REGISTRY_VALUE_CONTENT_FLAG"
            })
        o_regset_hook.set_result_verifier(evaluator)
        o_regcreate_hook.add_child_objective(o_regset_hook)

        o_net_send_hook = CapeTestObjective(test=self, objective_name="HookNetSend", is_informational=False)
        o_net_send_hook.set_success_msg("CAPE hooked windsock::send and retrieved the data sent")
        o_net_send_hook.set_failure_msg("There may be a hooking problem/change or the sample failed to run properly")
        evaluator = VerifyReportSectionHasMatching(
            path="behavior/processes/calls",
            match_criteria={
                "api": "send", 
                "arguments/value": "FLAG_NETWORK_SENT_DATA_FLAG"
            })
        o_net_send_hook.set_result_verifier(evaluator)
        o_has_behaviour_trace.add_child_objective(o_net_send_hook)


        o_mutex_hook = CapeTestObjective(test=self, objective_name="HookCreateMutex", is_informational=False)
        o_mutex_hook.set_success_msg("CAPE hooked Mutex creation and retrieved the name")
        o_mutex_hook.set_failure_msg("There may be a hooking problem/change or the sample failed to run properly")
        evaluator = VerifyReportSectionHasMatching(
            path="behavior/processes/calls",
            match_criteria={
                "api": "NtCreateMutant", 
                "arguments/value": "FLAG_MUTEX_NAME_FLAG"
            })
        o_mutex_hook.set_result_verifier(evaluator)
        o_has_behaviour_trace.add_child_objective(o_mutex_hook)


        # instead of searching for flags passed to specific API names,
        # we can widen the search to API categories
        o_key_hook = CapeTestObjective(test=self, objective_name="HookCryptFlag", is_informational=False)
        o_key_hook.set_success_msg("CAPE hooked a crypto API and retrieved the argument")
        o_key_hook.set_failure_msg("There may be a hooking problem/change or the sample failed to run properly")
        evaluator = VerifyReportSectionHasMatching(
            path="behavior/processes/calls",
            match_criteria={
                "category": "crypto", 
                "arguments/value": "FLAG_CRYPT_KEY_FLAG"
            })
        o_key_hook.set_result_verifier(evaluator)
        o_has_behaviour_trace.add_child_objective(o_key_hook)

        # Searching for exact flags can be risky - this one appears in the report with 
        # a null terminator. Using a regex finds it though.
        # Doing a string search VerifyReportHasPattern/VerifyReportHasExactString would also work
        o_mutex_hook = CapeTestObjective(test=self, objective_name="HookCryptData", is_informational=False)
        o_mutex_hook.set_success_msg("CAPE retrieved the data passed to a crypto operation")
        o_mutex_hook.set_failure_msg("There may be a hooking problem/change or the sample failed to run properly")
        evaluator = VerifyReportSectionHasMatching(
            path="behavior/processes/calls",
            match_criteria={
                "category": "crypto", 
                "arguments/value": "FLAG_CRYPT_PLAINTEXT_FLAG.*"
            },
            values_are_regexes=True)
        o_mutex_hook.set_result_verifier(evaluator)
        o_key_hook.add_child_objective(o_mutex_hook)



        
        

def print_objective_results(name, objinfo, indent = 0):
    print(f"{indent*' '}{name}: {objinfo['state']} ({objinfo['state_reason']})")
    for cname,cinfo in objinfo['children'].items():
        print_objective_results(cname, cinfo, indent=indent+4)

mytest = CapeDynamicTest("api_tracing_1", "exe")
mytest.evaluate_results(r"C:\Users\niaca\OneDrive\Documents\test_storedir")
results = mytest.get_results()
for obj,res in results.items():
    print_objective_results(obj, res, indent = 0)
