import oci
import argparse 
import json
import os
import logging
import csv
from typing import List, Dict, Any

logging.basicConfig(level=logging.INFO)

def load_config(config_file: str) -> Dict[str, Any]:
    """
    Load OCI configuration from the specified file.
    """
    try:
        config = oci.config.from_file(config_file)
        return config
    except oci.exceptions.ConfigFileNotFound as e:
        logging.error(f"Config file not found: {e}")
        raise

def write_output(data: List[Dict[str, Any]], output_file: str, verbose: bool, csv_format: bool, default_filename: str = None) -> None:
    """
    Write data to output file or print to stdout if verbose.
    If no output file is specified, use default_filename with appropriate extension.
    """
    if verbose:
        print(json.dumps(data, indent=4))
    
    # Generate default filename if none provided
    if output_file is None and default_filename is not None:
        extension = '.csv' if csv_format else '.json'
        output_file = f"{default_filename}{extension}"
        logging.info(f"No output file specified, using default: {output_file}")
    
    if output_file:
        if csv_format:
            if data:
                keys = data[0].keys()
                with open(output_file, 'w', newline='') as f:
                    dict_writer = csv.DictWriter(f, fieldnames=keys)
                    dict_writer.writeheader()
                    dict_writer.writerows(data)
                logging.info(f"Data written to CSV file: {output_file}")
            else:
                logging.warning("No data to write to CSV.")
        else:
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=4)
            logging.info(f"Data written to JSON file: {output_file}")

def list_compartments(config: Dict[str, Any], output_file: str = None, verbose: bool = False, csv_format: bool = False) -> List[Dict[str, Any]]:
    """
    List all compartments in the tenancy.
    """
    try:
        identity_client = oci.identity.IdentityClient(config)
        compartments = oci.pagination.list_call_get_all_results(identity_client.list_compartments, config["tenancy"]).data

        compartment_list = [{
            "id": compartment.id,
            "name": compartment.name,
            "description": compartment.description,
            "lifecycle_state": compartment.lifecycle_state,
            "time_created": compartment.time_created.isoformat()
        } for compartment in compartments]

        write_output(compartment_list, output_file, verbose, csv_format, "compartments")
        return compartment_list
    except oci.exceptions.ServiceError as e:
        if e.status == 401:
            logging.error(f"Authentication error: {e.message}")
            return []
        logging.error(f"Service error: {e}")
        raise

def list_compute_instances(config: Dict[str, Any], compartment_ids: List[str], output_file: str, verbose: bool, csv_format: bool) -> None:
    """
    List all compute instances in the specified compartments.
    """
    try:
        compute_client = oci.core.ComputeClient(config)
        instance_list = []

        for compartment_id in compartment_ids:
            instances = oci.pagination.list_call_get_all_results(compute_client.list_instances, compartment_id).data
            for instance in instances:
                instance_list.append({
                    "id": instance.id,
                    "display_name": instance.display_name,
                    "lifecycle_state": instance.lifecycle_state,
                    "time_created": instance.time_created.isoformat(),
                    "compartment_id": compartment_id
                })

        write_output(instance_list, output_file, verbose, csv_format, "compute_instances")
    except oci.exceptions.ServiceError as e:
        if e.status == 401:
            logging.error(f"Authentication error: {e.message}")
            return
        logging.error(f"Service error: {e}")
        raise

def list_oracle_dbs(config: Dict[str, Any], compartment_ids: List[str], output_file: str, verbose: bool, csv_format: bool) -> None:
    """
    List all Oracle databases in the specified compartments.
    """
    try:
        database_client = oci.database.DatabaseClient(config)
        db_list = []

        for compartment_id in compartment_ids:
            dbs = oci.pagination.list_call_get_all_results(database_client.list_autonomous_databases, compartment_id).data
            for db in dbs:
                db_list.append({
                    "id": db.id,
                    "display_name": db.display_name,
                    "lifecycle_state": db.lifecycle_state,
                    "db_workload": db.db_workload,
                    "time_created": db.time_created.isoformat(),
                    "compartment_id": compartment_id
                })

        write_output(db_list, output_file, verbose, csv_format, "oracle_databases")
    except oci.exceptions.ServiceError as e:
        if e.status == 401:
            logging.error(f"Authentication error: {e.message}")
            return
        logging.error(f"Service error: {e}")
        raise

def list_autonomous_databases(config: Dict[str, Any], compartment_ids: List[str], output_file: str, verbose: bool, csv_format: bool) -> None:
    """
    List all autonomous databases in the specified compartments.
    """
    try:
        database_client = oci.database.DatabaseClient(config)
        autonomous_db_list = []

        for compartment_id in compartment_ids:
            autonomous_dbs = oci.pagination.list_call_get_all_results(database_client.list_autonomous_databases, compartment_id).data
            for autonomous_db in autonomous_dbs:
                autonomous_db_list.append({
                    "id": autonomous_db.id,
                    "display_name": autonomous_db.display_name,
                    "lifecycle_state": autonomous_db.lifecycle_state,
                    "db_workload": autonomous_db.db_workload,
                    "time_created": autonomous_db.time_created.isoformat(),
                    "compartment_id": compartment_id
                })

        write_output(autonomous_db_list, output_file, verbose, csv_format, "autonomous_databases")
    except oci.exceptions.ServiceError as e:
        if e.status == 401:
            logging.error(f"Authentication error: {e.message}")
            return
        logging.error(f"Service error: {e}")
        raise

def check_permissions(identity_client, compartment_id):
    """
    Check if the user has permissions for the specified compartment.
    """
    try:
        identity_client.get_compartment(compartment_id)
        return True
    except oci.exceptions.ServiceError as e:
        if e.status == 403:
            return False
        raise

def exec_instance_console_command(config, compartment_id, instance_id, command_content, check_perms):
    """
    Execute a console command on the specified instance.
    """
    compute_client = oci.core.ComputeClient(config)
    identity_client = oci.identity.IdentityClient(config)

    if check_perms:
        if not check_permissions(identity_client, compartment_id):
            print(f"Permission denied for compartment: {compartment_id}")
            return
        print(f"Permissions are valid for compartment: {compartment_id}")
        return

    response = compute_client.instance_action(instance_id, "SOFTRESET")
    print(f"Instance {instance_id} console command executed: {response.data}")

def list_regions(config: Dict[str, Any], output_file: str = None, verbose: bool = False, csv_format: bool = False) -> List[str]:
    """
    List all regions available in OCI.
    """
    try:
        identity_client = oci.identity.IdentityClient(config)
        regions = identity_client.list_regions().data

        region_list = [{
            "name": region.name,
            "key": region.key
        } for region in regions]

        write_output(region_list, output_file, verbose, csv_format, "regions")
        return [region['name'] for region in region_list]
    except oci.exceptions.ServiceError as e:
        logging.error(f"Service error: {e}")
        raise

def list_compartments_all_regions(config: Dict[str, Any], output_file: str = None, verbose: bool = False, csv_format: bool = False) -> List[Dict[str, Any]]:
    """
    List all compartments in all regions.
    """
    try:
        regions = list_regions(config)
        all_compartments = []

        for region in regions:
            config["region"] = region
            try:
                compartments = list_compartments(config)
                all_compartments.extend(compartments)
            except oci.exceptions.ServiceError as e:
                if e.status == 401:
                    logging.error(f"Authentication error in region {region}: {e.message}")
                    continue
                logging.error(f"Service error in region {region}: {e}")
                raise

        write_output(all_compartments, output_file, verbose, csv_format, "compartments_all_regions")
        return all_compartments
    except oci.exceptions.ServiceError as e:
        logging.error(f"Service error: {e}")
        raise

def list_policies_for_user(config: Dict[str, Any], user_id: str, output_file: str = None, verbose: bool = False, csv_format: bool = False) -> None:
    """
    List all policies associated with the specified IAM user.
    """
    try:
        identity_client = oci.identity.IdentityClient(config)
        user_groups = oci.pagination.list_call_get_all_results(identity_client.list_user_group_memberships, compartment_id=config["tenancy"], user_id=user_id).data

        policy_list = []
        for user_group in user_groups:
            group_id = user_group.group_id
            policies = oci.pagination.list_call_get_all_results(identity_client.list_policies, compartment_id=config["tenancy"], group_id=group_id).data
            for policy in policies:
                policy_list.append({
                    "id": policy.id,
                    "name": policy.name,
                    "description": policy.description,
                    "statements": policy.statements,
                    "time_created": policy.time_created.isoformat()
                })

        write_output(policy_list, output_file, verbose, csv_format, f"policies_for_user_{user_id}")
    except oci.exceptions.ServiceError as e:
        if e.status == 401:
            logging.error(f"Authentication error: {e.message}")
            return
        logging.error(f"Service error: {e}")
        raise

def list_iam_policies(config: Dict[str, Any], compartment_id: str = None, output_file: str = None, verbose: bool = False, csv_format: bool = False) -> List[Dict[str, Any]]:
    """
    List all IAM policies in the specified compartment or all compartments if no compartment ID is provided.
    """
    try:
        identity_client = oci.identity.IdentityClient(config)
        policy_list = []

        if compartment_id:
            compartments = [compartment_id]
        else:
            compartments = [compartment['id'] for compartment in list_compartments(config)]

        for compartment in compartments:
            policies = oci.pagination.list_call_get_all_results(identity_client.list_policies, compartment_id=compartment).data
            for policy in policies:
                policy_list.append({
                    "id": policy.id,
                    "name": policy.name,
                    "description": policy.description,
                    "statements": policy.statements,
                    "time_created": policy.time_created.isoformat()
                })

        write_output(policy_list, output_file, verbose, csv_format, "iam_policies")
        return policy_list
    except oci.exceptions.ServiceError as e:
        if e.status == 401:
            logging.error(f"Authentication error: {e.message}")
            return []
        logging.error(f"Service error: {e}")
        raise

def list_iam_policies_all_regions(config: Dict[str, Any], output_file: str = None, verbose: bool = False, csv_format: bool = False) -> None:
    """
    List all IAM policies in all regions.
    """
    try:
        regions = list_regions(config)
        all_policies = []

        for region in regions:
            config["region"] = region
            try:
                policies = list_iam_policies(config)
                all_policies.extend(policies)
            except oci.exceptions.ServiceError as e:
                if e.status == 401:
                    logging.error(f"Authentication error in region {region}: {e.message}")
                    continue
                logging.error(f"Service error in region {region}: {e}")
                raise

        write_output(all_policies, output_file, verbose, csv_format, "iam_policies_all_regions")
    except oci.exceptions.ServiceError as e:
        logging.error(f"Service error: {e}")
        raise

def list_dynamic_groups(config: Dict[str, Any], output_file: str = None, verbose: bool = False, csv_format: bool = False) -> None:
    """
    List all dynamic groups in the current identity domain and their rules.
    """
    try:
        identity_client = oci.identity.IdentityClient(config)
        dynamic_groups = oci.pagination.list_call_get_all_results(identity_client.list_dynamic_groups, compartment_id=config["tenancy"]).data

        dynamic_group_list = [{
            "id": dynamic_group.id,
            "name": dynamic_group.name,
            "description": dynamic_group.description,
            "matching_rule": dynamic_group.matching_rule,
            "time_created": dynamic_group.time_created.isoformat()
        } for dynamic_group in dynamic_groups]

        write_output(dynamic_group_list, output_file, verbose, csv_format, "dynamic_groups")
    except oci.exceptions.ServiceError as e:
        if e.status == 401:
            logging.error(f"Authentication error: {e.message}")
            return
        logging.error(f"Service error: {e}")
        raise

def list_users(config: Dict[str, Any], output_file: str = None, verbose: bool = False, csv_format: bool = False) -> None:
    """
    List all users in the domain, including their details and group memberships.
    """
    try:
        identity_client = oci.identity.IdentityClient(config)
        compartment_id = config["tenancy"]
        users = oci.pagination.list_call_get_all_results(identity_client.list_users, compartment_id=compartment_id).data

        user_list = []
        for user in users:
            user_details = {
                "id": user.id,
                "name": user.name,
                "description": user.description,
                "email": user.email,
                "time_created": user.time_created.isoformat()
            }
            groups = oci.pagination.list_call_get_all_results(identity_client.list_user_group_memberships, compartment_id=compartment_id, user_id=user.id).data
            group_names = []
            for group in groups:
                group_details = identity_client.get_group(group.group_id).data
                group_names.append(f"{group_details.name} ({group.group_id})")
            user_details["groups"] = group_names
            user_list.append(user_details)

        write_output(user_list, output_file, verbose, csv_format, "users")
    except oci.exceptions.ServiceError as e:
        if e.status == 401:
            logging.error(f"Authentication error: {e.message}")
            return
        logging.error(f"Service error: {e}")
        raise

def list_domains(config: Dict[str, Any], output_file: str = None, verbose: bool = False, csv_format: bool = False) -> None:
    """
    List all available domains in the tenant.
    """
    try:
        identity_client = oci.identity.IdentityClient(config)
        domains = oci.pagination.list_call_get_all_results(identity_client.list_domains, compartment_id=config["tenancy"]).data

        domain_list = [{
            "id": domain.id,
            "display_name": domain.display_name,
            "description": domain.description,
            "time_created": domain.time_created.isoformat()
        } for domain in domains]

        write_output(domain_list, output_file, verbose, csv_format, "domains")
    except oci.exceptions.ServiceError as e:
        if e.status == 401:
            logging.error(f"Authentication error: {e.message}")
            return
        logging.error(f"Service error: {e}")
        raise

def list_groups(config: Dict[str, Any], output_file: str = None, verbose: bool = False, csv_format: bool = False) -> None:
    """
    List all groups in the current identity domain.
    """
    try:
        identity_client = oci.identity.IdentityClient(config)
        groups = oci.pagination.list_call_get_all_results(identity_client.list_groups, compartment_id=config["tenancy"]).data

        group_list = [{
            "id": group.id,
            "name": group.name,
            "description": group.description,
            "time_created": group.time_created.isoformat()
        } for group in groups]

        write_output(group_list, output_file, verbose, csv_format, "groups")
    except oci.exceptions.ServiceError as e:
        if e.status == 401:
            logging.error(f"Authentication error: {e.message}")
            return
        logging.error(f"Service error: {e}")
        raise

def list_reserved_public_ipv4_addresses(config: Dict[str, Any], compartment_ids: List[str], output_file: str = None, verbose: bool = False, csv_format: bool = False) -> None:
    """
    List all reserved public IPv4 addresses in the specified compartments.
    """
    try:
        virtual_network_client = oci.core.VirtualNetworkClient(config)
        ip_list = []

        for compartment_id in compartment_ids:
            logging.info(f"Checking compartment: {compartment_id}")
            public_ips = oci.pagination.list_call_get_all_results(
                virtual_network_client.list_public_ips,
                compartment_id=compartment_id,
                scope='REGION'
            ).data
            logging.info(f"Found {len(public_ips)} public IPs in compartment {compartment_id}")
            
            # Print all IPs immediately if verbose is enabled
            if verbose and public_ips:
                print(f"\nPublic IPs in compartment {compartment_id}:")
            
            for public_ip in public_ips:
                ip_data = {
                    "id": public_ip.id,
                    "ip_address": public_ip.ip_address,
                    "lifecycle_state": public_ip.lifecycle_state,
                    "time_created": public_ip.time_created.isoformat(),
                    "compartment_id": compartment_id
                }
                ip_list.append(ip_data)
                
                # Log each IP address
                logging.info(f"IP Address: {public_ip.ip_address}, State: {public_ip.lifecycle_state}")
                
                # Print each IP immediately if verbose is enabled
                if verbose:
                    print(f"  IP: {public_ip.ip_address}, State: {public_ip.lifecycle_state}")

        if not ip_list:
            msg = "No public IPs found in any compartment."
            logging.warning(msg)
            if verbose:
                print(msg)
        else:
            msg = f"Found a total of {len(ip_list)} public IPs."
            logging.info(msg)
            if verbose:
                print(f"\n{msg}")
        
        # Write all IPs to output
        write_output(ip_list, output_file, verbose, csv_format, "public_ipv4_addresses")
    except oci.exceptions.ServiceError as e:
        if e.status == 401:
            logging.error(f"Authentication error: {e.message}")
            return
        logging.error(f"Service error: {e}")
        raise

def list_private_ipv4_addresses(config: Dict[str, Any], compartment_ids: List[str], output_file: str = None, verbose: bool = False, csv_format: bool = False) -> None:
    """
    List all private IPv4 addresses in the specified compartments.
    """
    try:
        virtual_network_client = oci.core.VirtualNetworkClient(config)
        ip_list = []
        
        for compartment_id in compartment_ids:
            logging.info(f"Checking compartment: {compartment_id} for private IPs")
            
            # First, get all VCNs in the compartment
            vcns = oci.pagination.list_call_get_all_results(
                virtual_network_client.list_vcns,
                compartment_id=compartment_id
            ).data
            logging.info(f"Found {len(vcns)} VCNs in compartment {compartment_id}")
            
            for vcn in vcns:
                # Get all subnets for each VCN
                subnets = oci.pagination.list_call_get_all_results(
                    virtual_network_client.list_subnets,
                    compartment_id=compartment_id,
                    vcn_id=vcn.id
                ).data
                logging.info(f"Found {len(subnets)} subnets in VCN {vcn.display_name}")
                
                for subnet in subnets:
                    # Get all private IPs in the subnet
                    private_ips = oci.pagination.list_call_get_all_results(
                        virtual_network_client.list_private_ips,
                        subnet_id=subnet.id
                    ).data
                    logging.info(f"Found {len(private_ips)} private IPs in subnet {subnet.display_name}")
                    
                    # Print all IPs immediately if verbose is enabled
                    if verbose and private_ips:
                        print(f"\nPrivate IPs in subnet {subnet.display_name} (VCN: {vcn.display_name}):")
                    
                    for private_ip in private_ips:
                        ip_data = {
                            "id": private_ip.id,
                            "ip_address": private_ip.ip_address,
                            "display_name": getattr(private_ip, 'display_name', 'N/A'),
                            "hostname_label": getattr(private_ip, 'hostname_label', 'N/A'),
                            "is_primary": getattr(private_ip, 'is_primary', None),
                            "subnet_id": subnet.id,
                            "subnet_name": subnet.display_name,
                            "vcn_id": vcn.id,
                            "vcn_name": vcn.display_name,
                            "compartment_id": compartment_id
                        }
                        ip_list.append(ip_data)
                        
                        # Log each IP address
                        logging.info(f"Private IP: {private_ip.ip_address}")
                        
                        # Print each IP immediately if verbose is enabled
                        if verbose:
                            print(f"  IP: {private_ip.ip_address} (Primary: {getattr(private_ip, 'is_primary', 'N/A')})")

        if not ip_list:
            msg = "No private IPs found in any compartment."
            logging.warning(msg)
            if verbose:
                print(msg)
        else:
            msg = f"Found a total of {len(ip_list)} private IPs."
            logging.info(msg)
            if verbose:
                print(f"\n{msg}")
        
        # Write all IPs to output
        write_output(ip_list, output_file, verbose, csv_format, "private_ipv4_addresses")
    except oci.exceptions.ServiceError as e:
        if e.status == 401:
            logging.error(f"Authentication error: {e.message}")
            return
        logging.error(f"Service error: {e}")
        raise

def main():
    parser = argparse.ArgumentParser(description='OCI API script', add_help=True)
    parser.add_argument('action', choices=['list-compartments', 'list-compartments-all-regions', 'list-compute-instances', 
                                           'list-oracle-dbs', 'list-autonomousdatabases', 'exec-icc', 'list-regions', 
                                           'list-policies-for-user', 'list-iam-policies', 'list-iam-policies-all-regions', 
                                           'list-dynamic-groups', 'list-users', 'list-domains', 'list-groups', 
                                           'list-reserved-public-ipv4-addresses', 'list-private-ipv4-addresses'], 
                        help='Action to perform')
    parser.add_argument('--config-file', required=True, help='Path to the OCI config file')
    parser.add_argument('--output-file', required=False, help='Path to the output file')
    parser.add_argument('--verbose', action='store_true', help='Output results to STDOUT')
    parser.add_argument('--compartment-id', help='Compartment ID for listing compute instances, Oracle databases, or reserved public IPv4 addresses')
    parser.add_argument('--region', help='Region to search in')
    parser.add_argument('--check-perms', action='store_true', help='Check permissions and display them only')
    parser.add_argument('--instance-id', help='Instance ID for executing console command')
    parser.add_argument('--command-content', help='Content of the console command to execute')
    parser.add_argument('--csv', action='store_true', help='Output results in CSV format')
    parser.add_argument('--user-id', help='User ID for listing policies associated with the IAM user')

    args = parser.parse_args()

    config = load_config(args.config_file)
    
    if args.region:
        config["region"] = args.region

    if args.action == 'list-compartments':
        list_compartments(config, args.output_file, args.verbose, args.csv)
    elif args.action == 'list-compartments-all-regions':
        list_compartments_all_regions(config, args.output_file, args.verbose, args.csv)
    elif args.action == 'list-compute-instances':
        compartment_ids = [args.compartment_id] if args.compartment_id else list_compartments(config)
        list_compute_instances(config, compartment_ids, args.output_file, args.verbose, args.csv)
    elif args.action == 'list-oracle-dbs':
        compartment_ids = [args.compartment_id] if args.compartment_id else list_compartments(config)
        list_oracle_dbs(config, compartment_ids, args.output_file, args.verbose, args.csv)
    elif args.action == 'list-autonomousdatabases':
        compartment_ids = [args.compartment_id] if args.compartment_id else list_compartments(config)
        list_autonomous_databases(config, compartment_ids, args.output_file, args.verbose, args.csv)
    elif args.action == 'exec-icc':
        if not args.instance_id or not args.command_content:
            parser.error('exec-icc action requires --instance-id and --command-content')
        exec_instance_console_command(config, args.compartment_id, args.instance_id, args.command_content, args.check_perms)
    elif args.action == 'list-regions':
        list_regions(config, args.output_file, args.verbose, args.csv)
    elif args.action == 'list-policies-for-user':
        if not args.user_id:
            parser.error('list-policies-for-user action requires --user-id')
        list_policies_for_user(config, args.user_id, args.output_file, args.verbose, args.csv)
    elif args.action == 'list-iam-policies':
        list_iam_policies(config, args.compartment_id, args.output_file, args.verbose, args.csv)
    elif args.action == 'list-iam-policies-all-regions':
        list_iam_policies_all_regions(config, args.output_file, args.verbose, args.csv)
    elif args.action == 'list-dynamic-groups':
        list_dynamic_groups(config, args.output_file, args.verbose, args.csv)
    elif args.action == 'list-users':
        list_users(config, args.output_file, args.verbose, args.csv)
    elif args.action == 'list-domains':
        list_domains(config, args.output_file, args.verbose, args.csv)
    elif args.action == 'list-groups':
        list_groups(config, args.output_file, args.verbose, args.csv)
    elif args.action == 'list-reserved-public-ipv4-addresses':
        compartment_ids = [args.compartment_id] if args.compartment_id else [compartment['id'] for compartment in list_compartments(config)]
        list_reserved_public_ipv4_addresses(config, compartment_ids, args.output_file, args.verbose, args.csv)
    elif args.action == 'list-private-ipv4-addresses':
        compartment_ids = [args.compartment_id] if args.compartment_id else [compartment['id'] for compartment in list_compartments(config)]
        list_private_ipv4_addresses(config, compartment_ids, args.output_file, args.verbose, args.csv)

if __name__ == "__main__":
    main()