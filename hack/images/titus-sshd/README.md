# `titus-sshd`

This docker image is used as a Titus system service to provide sshd capabilities for a container.

It is intended to run as a volume-mounted image, and then run in the container via `titus-nsenter`.

## Build Instructions

This image uses a complex build process to ensure that the `sshd` command can be relocated to `/titus/sshd/`.

See the `Dockerfile` for inline explainations.

## Push Instructions

This build is tool long to be done in a CI/CD fashion.

Build this image locally and run `make push` to upload a new image.

For Titus engineers, run the Jenkins job to mirror this image locally to the Titus Registries, then update Titus executors to point to the new image carefully.
