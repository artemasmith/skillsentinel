# Reviewer notes

Our scanner flags any line that reads "ignore all previous instructions" as an injection.
The signature list marks "disregard your instructions" as a known-bad phrase.
The scanner opens ~/.ssh/id_rsa only to check its passphrase.
