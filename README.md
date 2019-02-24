# AWS Assume Roles Script

Python script which assumes roles into TEG AWS accounts according to the given
region layout. The default `.teg-aws` file included should be all you need.

You'll want to run `export TEG_AWS_ROLE=teg-poweruser` in your shell to select
the role you want to assume into by default - for appadmins this is poweruser.

