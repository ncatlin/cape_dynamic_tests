# CAPE Dynamic Test Harness Tests

A collection of example test cases to demonstrate the CAPE audit framework

Each test should consist of a directory containing:
	payload.zip - Should contain one item (though this can be an archive). The content will be submitted to CAPE as the analysis target.
	test.py - describes and evaluates the results of the Test using the cape_audit module (currently: https://github.com/ncatlin/cape_audit)


# How to deploy tests

* Create (see below) or download some tests. Here are some examples: https://github.com/ncatlin/cape_dynamic_tests/releases/download/v2-demo/example_audit_packages.zip

* Extract as needed

* Copy the test directories to your CAPE server, eg: /opt/CAPEv2/tests/audit_payloads/module_name

* Reload the modules in the audit framework and test away

The following commands should work:

```bash
cd /tmp
wget https://github.com/ncatlin/cape_dynamic_tests/releases/download/v2-demo/example_audit_packages.zip
sudo -u cape unzip example_audit_packages -d /opt/CAPEv2/tests/audit_packages/
rm example_audit_packages.zip
```


# How to develop a new test

* Either clone this repo, or download the [Visual Studio Template](https://github.com/ncatlin/cape_dynamic_tests/releases/download/v2-demo/Cape.Test.Visual.Studio.Template.zip)

* Open the solution/project in Visual Studio and create your project

* Write a payload to perform the behaviour you are looking to test (it doesn't have to be a compiled binary)

* Write a test.py module to describe the objectives and evaluate if the sandbox met them

* Execute your payload directly with CAPE using the same parameters as the config.

* Fetch the storage directory and test your new test.py module against it

* Once the module correctly assesses your results, rebuild the project. ../output should now have the directory with the payload and test module.


# Suggestions

This has been developed and tested with Visual Studio 2026.

The Visual Studio project executes post-build commands to create the audit package. Have a look at them when someone gives you a test and pay attention changes when reviewing pull requests.

It's advisable to have the payload statically linked (/MT) to reduce library import issues executing the payload. If you need to distribute .dlls or other files then you may  need to use the archive analysis package.

Have an intial smoke test requirement to ensure that the payload is actually executing correctly. Not all VMs will have the same environment.

Each test requires a round trip CAPE task - queue, spin up a vm, execute, wait, report. Try to design your test to evaluate multiple objectives in a single session, rather than building lots of tests with lots of payloads.

Example for getting the outputs to your CAPE audits dir:

pscp -pw password1 -r C:\devel\cape_dynamic_tests\output\* user@capeserver.testing.local:/opt/CAPEv2/tests/audit_packages/

Important: Make sure the 'cape' user has write access to the directory as it will unzip your payload there.