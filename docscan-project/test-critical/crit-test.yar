/* Test-only critical rule for CI (hostile_run.py): the common grif phrase.
   The real phrase rules are an E5Search requirement and are not in this repository. */
rule crit_test_grif
{
    strings:
        $m = /службов[^ ]{0,12} користуванн[^ ]{0,8}/
    condition:
        $m
}
