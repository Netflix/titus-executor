
# The following variables can be used so order-only dependencies can be
# specified without forcing PHONY targets to run every time.

# was the 'builder' target in the command line?
builder=$(filter builder,$(MAKECMDGOALS))

# was the 'clean' target in the command line?
clean=$(filter clean,$(MAKECMDGOALS))

# was the 'clean' target in the command line?
clean_proto_defs=$(filter clean-proto-defs,$(MAKECMDGOALS))
