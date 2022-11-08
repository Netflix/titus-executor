refresh: creds fetch generate

creds:
	newt --app-type awscreds refresh -r arn:aws:iam::686589254418:role/titus_us_east_1_agents_test_titus titus_us_east_1_agents_test

.PHONY: fetch
fetch: instances.json
instances.json:
	@echo "Fetching ec2 instance definitions..."
	aws --region=us-east-1 --profile=titus_us_east_1_agents_test ec2 describe-instance-types > $@

generate:
	./generate.py
	go fmt instance_limits.go

clean:
	rm instances.json instance_limits.go
