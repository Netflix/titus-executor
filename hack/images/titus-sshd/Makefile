build:
	docker build -t titusoss/titus-sshd .

dev: build
	docker run -it $(shell docker build -q .) /titus/sshd/bin/busybox sh

itest: build
	# Uses the -T (test) option of sshd to ensure everything is compiled correctly
	# And the config file, keys, etc are all good to go
	docker run -it -v sshd_config.itest:/titus/etc/ssh/sshd_config:ro $(shell docker build -q .) \
	  /titus/sshd/run-titus-sshd -T && echo "PASS: titus-sshd environment validated"

push: build
	docker push titusoss/titus-sshd
	# For netflix engineers to publish locally
	newt --app-type=docker-image publish --image-name=titusoss/titus-sshd
