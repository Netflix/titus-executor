package vpc

// Interfaces, and IPs per interface comes from https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html#AvailableIpPerENI
var interfaceLimits = map[string]limits{
	"p4d.24xlarge": {
		interfaces:              15,
		ipAddressesPerInterface: 50,
		networkThroughput:       400000,
		branchENIs:              120,
	},
	"g4dn.xlarge": {
		interfaces:              3,
		ipAddressesPerInterface: 10,
		networkThroughput:       5000,
		branchENIs:              10,
	},
	"g4dn.2xlarge": {
		interfaces:              3,
		ipAddressesPerInterface: 10,
		networkThroughput:       10000,
		branchENIs:              20,
	},
	"g4dn.4xlarge": {
		interfaces:              3,
		ipAddressesPerInterface: 10,
		networkThroughput:       20000,
		branchENIs:              60,
	},
	"g4dn.8xlarge": {
		interfaces:              4,
		ipAddressesPerInterface: 15,
		networkThroughput:       50000,
		branchENIs:              60,
	},
	"g4dn.12xlarge": {
		interfaces:              8,
		ipAddressesPerInterface: 30,
		networkThroughput:       50000,
		branchENIs:              60,
	},
	"g4dn.16xlarge": {
		interfaces:              15,
		ipAddressesPerInterface: 50,
		networkThroughput:       50000,
		branchENIs:              120,
	},
	"g4dn.metal": {
		interfaces:              15,
		ipAddressesPerInterface: 50,
		networkThroughput:       100000,
		branchENIs:              120,
	},
	"g5.48xlarge": {
		interfaces:              15,
		ipAddressesPerInterface: 50,
		networkThroughput:       100000,
		branchENIs:              120,
	},
	"m5.large": {
		interfaces:              3,
		ipAddressesPerInterface: 10,
		networkThroughput:       100,
		branchENIs:              10,
	},
	"m5.xlarge": {
		interfaces:              4,
		ipAddressesPerInterface: 15,
		networkThroughput:       1000,
		branchENIs:              20,
	},
	"m5.2xlarge": {
		interfaces:              4,
		ipAddressesPerInterface: 15,
		networkThroughput:       1000,
		branchENIs:              40,
	},
	"m5.4xlarge": {
		interfaces:              8,
		ipAddressesPerInterface: 30,
		networkThroughput:       2000,
		branchENIs:              60,
	},
	"m5.12xlarge": {
		interfaces:              8,
		ipAddressesPerInterface: 30,
		// Is this number correct?
		networkThroughput: 10000,
		branchENIs:        60,
	},
	"m5.24xlarge": {
		interfaces:              15,
		ipAddressesPerInterface: 50,
		networkThroughput:       23000,
		branchENIs:              120,
	},
	"m5.metal": {
		interfaces:              12,
		ipAddressesPerInterface: 50,
		networkThroughput:       25000,
		branchENIs:              198,
	},
	"r5.large": {
		interfaces:              3,
		ipAddressesPerInterface: 10,
		networkThroughput:       1000,
		branchENIs:              10,
	},
	"r5.xlarge": {
		interfaces:              4,
		ipAddressesPerInterface: 15,
		networkThroughput:       1000,
		branchENIs:              20,
	},
	"r5.2xlarge": {
		interfaces:              4,
		ipAddressesPerInterface: 15,
		networkThroughput:       2000,
		branchENIs:              40,
	},
	"r5.4xlarge": {
		interfaces:              8,
		ipAddressesPerInterface: 30,
		networkThroughput:       4000,
		branchENIs:              60,
	},
	"r5.12xlarge": {
		interfaces:              8,
		ipAddressesPerInterface: 30,
		networkThroughput:       9000,
		branchENIs:              60,
	},
	"r5.24xlarge": {
		interfaces:              15,
		ipAddressesPerInterface: 50,
		networkThroughput:       23000,
		branchENIs:              120,
	},
	"r5.metal": {
		interfaces:              12,
		ipAddressesPerInterface: 50,
		networkThroughput:       25000,
		branchENIs:              198,
	},
	"c5.large": {
		interfaces:              3,
		ipAddressesPerInterface: 10,
		// Maybe?
		networkThroughput: 1000,
	},
	"c5.xlarge": {
		interfaces:              4,
		ipAddressesPerInterface: 15,
		networkThroughput:       2000,
	},
	"c5.2xlarge": {
		interfaces:              4,
		ipAddressesPerInterface: 15,
		networkThroughput:       2000,
	},
	"c5.4xlarge": {
		interfaces:              4,
		ipAddressesPerInterface: 30,
		networkThroughput:       4000,
	},
	"c5.9xlarge": {
		interfaces:              4,
		ipAddressesPerInterface: 30,
		networkThroughput:       10000,
	},
	"c5.18xlarge": {
		interfaces:              4,
		ipAddressesPerInterface: 50,
		networkThroughput:       23000,
	},
}
