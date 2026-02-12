from cape_audit import CapeDynamicTestBase, CapeTestObjective, OSTarget
from cape_audit.verifiers import VerifyReportSectionHasMatching


class CapeDynamicTest(CapeDynamicTestBase):
    def __init__(self):
        super().__init__(test_name="debugger_detection_win", analysis_package="exe")
        self.set_description(
            "Runs through some debugger detection techniques to see if they will find the CAPE debugger"
        )
        self.set_payload_notes(
            "A single statically linked 64-bit PE binary, tested on Windows 10 and 11."
        )
        self.set_result_notes(
            "None of these should be detected by default on modern versions of windows."
        )
        self.set_zip_password(None)
        self.set_task_timeout_seconds(120)
        self.set_os_targets([OSTarget.WINDOWS])
        self.set_enforce_timeout(False)
        self.set_task_config(
            {
                "Route": None,
                "Tags": ["win10", "x64"],
                "Request Options": "",
                "Custom Request Params": None,
            }
        )
        self._init_objectives()

    def _init_objectives(self):

        o_debugger_working = CapeTestObjective(
            test=self,
            requirement="debugger_is_working",
            objective_name="API calls are being intercepted",
        )
        o_debugger_working.set_success_msg(
            "CAPE's monitor is attached to the process and intercepting API calls"
        )
        o_debugger_working.set_failure_msg(
            "CAPE did not recieve debugger output from the process or there was an analysis error."
        )
        evaluator = VerifyReportSectionHasMatching(
            path="behavior/processes/calls",
            match_criteria=[
                {"api": "OutputDebugStringA"},
                {"arguments/value": r"FLAG_DBG_PAYLOAD_STARTED_SUCCESS"},
            ],
        )
        o_debugger_working.set_result_verifier(evaluator)
        self.add_objective(o_debugger_working)

        o_is_debugger_present = CapeTestObjective(
            test=self,
            requirement="Evades IsDebuggerPresent",
            objective_name="IsDebuggerPresent",
        )
        o_is_debugger_present.set_success_msg(
            "Calls to IsDebuggerPresent return false while debugged by CAPE's monitor"
        )
        o_is_debugger_present.set_failure_msg(
            "IsDebuggerPresent is returning true under CAPE analysis"
        )
        evaluator = VerifyReportSectionHasMatching(
            path="behavior/processes/calls",
            match_criteria=[
                {"api": "OutputDebugStringA"},
                {"arguments/value": r"FLAG_DBG_UNDETECTED_ISDBPR_FLAG"},
            ],
        )
        o_is_debugger_present.set_result_verifier(evaluator)
        o_debugger_working.add_child_objective(o_is_debugger_present)

        o_is_remote_debugger_present = CapeTestObjective(
            test=self,
            requirement="Evades CheckRemoteDebuggerPresent",
            objective_name="CheckRemoteDebuggerPresent",
        )
        o_is_remote_debugger_present.set_success_msg(
            "Calls to CheckRemoteDebuggerPresent return false while debugged by CAPE's monitor"
        )
        o_is_remote_debugger_present.set_failure_msg(
            "CheckRemoteDebuggerPresent is returning true under CAPE analysis"
        )
        evaluator = VerifyReportSectionHasMatching(
            path="behavior/processes/calls",
            match_criteria=[
                {"api": "OutputDebugStringA"},
                {"arguments/value": r"FLAG_DBG_UNDETECTED_ISRDBP_FLAG"},
            ],
        )
        o_is_remote_debugger_present.set_result_verifier(evaluator)
        o_debugger_working.add_child_objective(o_is_remote_debugger_present)

        o_process_dbg_port = CapeTestObjective(
            test=self,
            requirement="NtQueryInformationProcess(ProcessDebugPort) is unsuccessful",
            objective_name="NTQ_ProcessDebugPort",
        )
        o_process_dbg_port.set_success_msg(
            "Querying ProcessDebugPort via NtQueryInformationProcess did not reveal a debugger"
        )
        o_process_dbg_port.set_failure_msg(
            "Querying ProcessDebugPort via NtQueryInformationProcess returned a non-error result"
        )
        evaluator = VerifyReportSectionHasMatching(
            path="behavior/processes/calls",
            match_criteria=[
                {"api": "OutputDebugStringA"},
                {"arguments/value": r"FLAG_DBG_UNDETECTED_NTQIPPDB_FLAG"},
            ],
        )
        o_process_dbg_port.set_result_verifier(evaluator)
        o_debugger_working.add_child_objective(o_process_dbg_port)

        o_process_dbg_flags = CapeTestObjective(
            test=self,
            requirement="NtQueryInformationProcess(ProcessDebugFlags) does not return a set flag",
            objective_name="NTQ_ProcessDebugFlag",
        )
        o_process_dbg_flags.set_success_msg(
            "Querying ProcessDebugFlags via NtQueryInformationProcess did not reveal a debugger"
        )
        o_process_dbg_flags.set_failure_msg(
            "Querying ProcessDebugFlags via NtQueryInformationProcess output a set debugger flag"
        )
        evaluator = VerifyReportSectionHasMatching(
            path="behavior/processes/calls",
            match_criteria=[
                {"api": "OutputDebugStringA"},
                {"arguments/value": r"FLAG_DBG_UNDETECTED_NTQIPPDF_FLAG"},
            ],
        )
        o_process_dbg_flags.set_result_verifier(evaluator)
        o_debugger_working.add_child_objective(o_process_dbg_flags)

        o_process_dbg_obj = CapeTestObjective(
            test=self,
            requirement="NtQueryInformationProcess(ProcessDebugObjHandle) does not return a handle",
            objective_name="NTQ_ProcessDebugObjHandle",
        )
        o_process_dbg_obj.set_success_msg(
            "NtQueryInformationProcess(ProcessDebugObjHandle) did not return a debug object handle"
        )
        o_process_dbg_obj.set_failure_msg(
            "NtQueryInformationProcess(ProcessDebugObjHandle) returned a debug object handle"
        )
        evaluator = VerifyReportSectionHasMatching(
            path="behavior/processes/calls",
            match_criteria=[
                {"api": "OutputDebugStringA"},
                {"arguments/value": r"FLAG_DBG_UNDETECTED_NTQIPDOH_FLAG"},
            ],
        )
        o_process_dbg_obj.set_result_verifier(evaluator)
        o_debugger_working.add_child_objective(o_process_dbg_obj)

        o_process_dbg_obj = CapeTestObjective(
            test=self,
            requirement="Heap flags do not show evidence of debugger presence",
            objective_name="Heap_flags_dbg_pre_win10",
        )
        o_process_dbg_obj.set_success_msg(
            "Heap flags appeared identical to those of an undebugged processed. Test unlikely to fail in modern windows."
        )
        o_process_dbg_obj.set_failure_msg(
            "Heap flags showed evidence of debugger activity. This is likely an older (<10) version of windows."
        )
        evaluator = VerifyReportSectionHasMatching(
            path="behavior/processes/calls",
            match_criteria=[
                {"api": "OutputDebugStringA"},
                {"arguments/value": r"FLAG_DBG_UNDETECTED_HPFLGPRE10_FLAG"},
            ],
        )
        o_process_dbg_obj.set_result_verifier(evaluator)
        o_debugger_working.add_child_objective(o_process_dbg_obj)

        o_kuser_mem_debug = CapeTestObjective(
            test=self,
            requirement="KUSER_SHARED_DATA checks do not reveal a kernel debugger",
            objective_name="kuser_shared_kernel_debugger",
        )
        o_kuser_mem_debug.set_success_msg(
            "No evidence of a system debugger was found in KUSER_SHARED_DATA"
        )
        o_kuser_mem_debug.set_failure_msg(
            "Bit 0 or 1 of 0x7ffe02d4 was found to be set, possibly by a kernel debugger."
        )
        evaluator = VerifyReportSectionHasMatching(
            path="behavior/processes/calls",
            match_criteria=[
                {"api": "OutputDebugStringA"},
                {"arguments/value": r"FLAG_DBG_UNDETECTED_KUSERKERNDBG_FLAG"},
            ],
        )
        o_kuser_mem_debug.set_result_verifier(evaluator)
        o_debugger_working.add_child_objective(o_kuser_mem_debug)


if __name__ == "__main__":
    mytest = CapeDynamicTest()
    # developers: change me
    mytest.evaluate_results(r"[path_to_task_store_dir_after_payload_analysis]")
    mytest.print_test_results()
