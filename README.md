# ConWeave P4-16 Repository

This is a Github repository for the SIGCOMM'23 paper "[Network Load Balancing with In-network Reordering Support for RDMA](https://doi.org/10.1145/3603269.3604849)".

This repository incudes p4 programs of ConWeave. 
We used `BF-SDE-9.11.1` to compile and run the program.

### Resource Consumption on Tofino2
* `leaf_conweave_resource` is a repo to solely evaluate the data-plane resource consumption of ConWeave mechanism.
* `leaf_conweave_resource/mau.resources.log` is the output log files, showing percentages of resource consumption based on `p4-build`.

### Artifact - P4 Source Code
`leaf_conweave` is a repo of ConWeave p4 source code running on leaf (ToR) switches.

**_NOTE:_** The current repository is simply provided as a reference code. 
It would be hard to exactly reproduce the testbed setup and evaluation results in the paper because of our complex testbed environment (e.g., by virtualized topology and its adapted codebase).

For artifact evaluation, feel free to skip this as the majority of results in the paper are executed by RDMA NS-3 simulator that allows integrating various environment conditions that are hard to be done on physical testbed, and prevent randomness for fair comparative studies versus baseline existing solutions.

In near future, we will provide a _simplified_ program that can be run on simple testbed and easily reproducible. 