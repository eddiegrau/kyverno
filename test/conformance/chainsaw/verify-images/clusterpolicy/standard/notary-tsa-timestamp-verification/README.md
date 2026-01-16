## Description

This test validates that Notary image verification policies with TSA (Timestamp Authority) certificate configuration are accepted and work correctly. The test verifies:

1. Policy with `tsaCert` and `verifyTimestamp` fields is accepted
2. Image verification works when TSA configuration is present (falls back to CA-only verification when image has no timestamp)

## Expected Behavior

The policy should be created successfully with TSA configuration fields. When verifying images without timestamps, verification falls back to certificate-based verification only.

## Reference

- GitHub Issue: https://github.com/kyverno/kyverno/issues/14679
