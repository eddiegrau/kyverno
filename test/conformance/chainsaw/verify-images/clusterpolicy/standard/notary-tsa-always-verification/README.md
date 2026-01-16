## Description

This test validates that Notary image verification policies with `verifyTimestamp: always` configuration are accepted. This mode requires timestamps to always be present and verified.

Note: Since the test image does not have RFC 3161 timestamps, this test verifies that the policy is accepted and applied, but the verification will fail due to missing timestamps. This is expected behavior.

## Expected Behavior

The policy should be created successfully. Pod creation should be rejected because the image signature lacks the required timestamp when `verifyTimestamp: always` is set.

## Reference

- GitHub Issue: https://github.com/kyverno/kyverno/issues/14679
