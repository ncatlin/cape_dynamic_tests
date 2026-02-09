from cape_audit import CapeDynamicTestBase, CapeTestObjective, OSTarget
from cape_audit.verifiers import VerifyReportSectionHasContent, VerifyReportHasPattern

import re

class CapeDynamicTest(CapeDynamicTestBase):
    def __init__(self):
        super().__init__(test_name="template_cape_test", analysis_package="exe")
        self.set_description("Simple example test that checks for an API call in a CAPE task report")
        self.set_payload_notes("A single statically linked 64-bit PE binary, tested on Windows 10.")
        self.set_result_notes("Requirement will be met if CAPE is working")

        # Set a password if you payload causes AV issues
        # you will need to configure this in the project build steps as well
        # Project properties -> Build Events -> Post-Build Event -> Command line
        # The default windows tar command does not support passwords, so you will need to use an alternative
        # eg: "7z.exe" a -tzip -p"YourPassword" -mem=ZipCrypto "%TEST_OUTPUT_DIR%\payload.zip" "$(OutDir)$(TargetFileName)"
        self.set_zip_password(None)
        self.set_os_targets([OSTarget.WINDOWS])
        self.set_task_timeout_seconds(120)
        self.set_enforce_timeout(False)
        self.set_task_config({
              "Route": None,
              "Tags": [ "win10","x64"],
              "Request Options": "",
              "Custom Request Params": None
          })
        self._init_objectives()

    def _init_objectives(self):

        # Check if there are any behavioural listings at all in the report
        o_has_behaviour_trace = CapeTestObjective(test=self, 
                                                  requirement="API calls are being hooked", 
                                                  objective_name="BehaviourInfoGenerated")
        o_has_behaviour_trace.set_success_msg("API hooking is working")
        o_has_behaviour_trace.set_failure_msg("The sample failed to execute, the monitor failed\
                                         to initialise or API hooking is not working")
        o_has_behaviour_trace.set_result_verifier(VerifyReportSectionHasContent("behavior"))
        self.add_objective(o_has_behaviour_trace)


        # If it does, then check if I/O content is retrieved
        o_console_write = CapeTestObjective(test=self, 
                                            requirement="I/O APIs are hooked",
                                           objective_name="DetectConsoleWrite")
        o_console_write.set_success_msg("CAPE hooked the API call and retrieved the argument")
        o_console_write.set_failure_msg("There may be a hooking problem/change or the sample failed to run properly")
        o_console_write.set_result_verifier(VerifyReportHasPattern(pattern=re.compile("FLAG_WRITECONSOLE_FLAG")))
        o_has_behaviour_trace.add_child_objective(o_console_write)


if __name__ == "__main__":
    mytest = CapeDynamicTest()
    # developers: change me
    mytest.evaluate_results(r"[path_to_task_store_dir_after_payload_analysis]")
    mytest.print_test_results()
