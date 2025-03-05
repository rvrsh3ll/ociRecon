# ociRecon

A Python tool for discovering and managing various Oracle Cloud Infrastructure (OCI) resources using the OCI API. ociRecon helps security professionals, cloud administrators, and auditors efficiently enumerate and document OCI resources across compartments and regions.

## Features

- **Comprehensive Resource Discovery:** Enumerate compartments, compute instances, databases, users, groups, and more
- **Cross-Region Functionality:** Operate across multiple OCI regions with a single command 
- **Flexible Output Options:** Generate JSON or CSV output files for further analysis
- **Permission Testing:** Check access rights to different compartments and resources
- **IAM Analysis:** Review users, groups, policies, and dynamic groups

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/rvrsh3ll/ociRecon.git
   cd ociRecon
   ```

2. Install the required dependencies:
   ```
   pip install oci
   ```

## Configuration

ociRecon requires a valid OCI configuration file. You can create this using the OCI CLI setup process:

1. Follow the [OCI SDK documentation](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm) to create your config file
2. By default, it is stored in `~/.oci/config` on Linux/macOS or `%USERPROFILE%\.oci\config` on Windows

## Usage Examples

### List Compartments

List all compartments in the tenancy:
```
python ociRecon.py list-compartments --config-file ~/.oci/config --verbose
```

List compartments across all regions:
```
python ociRecon.py list-compartments-all-regions --config-file ~/.oci/config --output-file all_compartments.json
```

### List Compute Resources

List all compute instances in a specific compartment:
```
python ociRecon.py list-compute-instances --config-file ~/.oci/config --compartment-id ocid1.compartment.oc1..example --output-file instances.json
```

### Database Reconnaissance

List all Oracle databases:
```
python ociRecon.py list-oracle-dbs --config-file ~/.oci/config --verbose --csv
```

List autonomous databases:
```
python ociRecon.py list-autonomousdatabases --config-file ~/.oci/config --output-file autonomous_dbs.csv --csv
```

### IAM Reconnaissance

List all users and their group memberships:
```
python ociRecon.py list-users --config-file ~/.oci/config --verbose
```

List groups:
```
python ociRecon.py list-groups --config-file ~/.oci/config --output-file groups.json
```

List IAM policies:
```
python ociRecon.py list-iam-policies --config-file ~/.oci/config --verbose
```

List IAM policies across all regions:
```
python ociRecon.py list-iam-policies-all-regions --config-file ~/.oci/config --output-file all_policies.json
```

List dynamic groups:
```
python ociRecon.py list-dynamic-groups --config-file ~/.oci/config --verbose
```

### Network Reconnaissance

List all reserved public IPv4 addresses:
```
python ociRecon.py list-reserved-public-ipv4-addresses --config-file ~/.oci/config --verbose
```

List all private IPv4 addresses:
```
python ociRecon.py list-private-ipv4-addresses --config-file ~/.oci/config --output-file private_ips.csv --csv
```

## Command Line Options

- `--config-file`: Path to the OCI config file (required)
- `--output-file`: Path to the output file (if not specified, generates default filename)
- `--verbose`: Output results to STDOUT
- `--csv`: Output results in CSV format (default is JSON)
- `--compartment-id`: Compartment ID for operations that require it
- `--region`: Region to search in
- `--check-perms`: Check permissions and display them only
- `--user-id`: User ID for listing policies associated with the IAM user

## Available Actions

- `list-compartments`: List all compartments in the tenancy
- `list-compartments-all-regions`: List compartments across all regions
- `list-compute-instances`: List all compute instances
- `list-oracle-dbs`: List all Oracle databases
- `list-autonomousdatabases`: List all autonomous databases
- `list-regions`: List all available regions
- `list-policies-for-user`: List policies for a specific user
- `list-iam-policies`: List IAM policies in a compartment or all compartments
- `list-iam-policies-all-regions`: List IAM policies across all regions
- `list-dynamic-groups`: List all dynamic groups
- `list-users`: List all users and their group memberships
- `list-domains`: List all available domains
- `list-groups`: List all groups
- `list-reserved-public-ipv4-addresses`: List all reserved public IPv4 addresses
- `list-private-ipv4-addresses`: List all private IPv4 addresses

## License

This project is licensed under the BSD 2-Clause License - see the LICENSE file for details.
