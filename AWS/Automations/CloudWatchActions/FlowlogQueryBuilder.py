from Automations.Utils.isip import isip
import re


def get_private_ips_for_interface_ids(session, interface_ids):
    ec2_client = session.client('ec2')
    interface_to_ip_mapping = dict()

    # Describe network interfaces to get private IP addresses
    response = ec2_client.describe_network_interfaces(
        NetworkInterfaceIds=interface_ids)
    for interface in response['NetworkInterfaces']:
        interface_to_ip_mapping[
            interface["NetworkInterfaceId"]
        ] = interface['PrivateIpAddress']

    ec2_client.close()
    return interface_to_ip_mapping


def flowlog_query_builder(
        session=None,
        dst_addr=None,
        interface_ids=None,
        dst_port=None,
        exclude_private_ips_from_source=False,
        exclude_src_ports=False,
        matching_interface_ip_with_destaddr_ip=True
):
    """
    This function build cloud watch log query for vpc flow logs

    :param dst_addr: The address that the traffic was targeted to
    :param interface_ids: The eni that this traffic was recorded on
    :param dst_port: The targeted port
    :param exclude_private_ips_from_source: A flag to mark if to exclude private ips
    :param matching_interface_ip_with_destaddr_ip: A flag to mark if to match interface ids ip address with destAddr
    :return:
    """
    base_filter = (
        '  filter action="ACCEPT" '
        " | filter dstPort<=1024 or (dstPort>1024 and srcPort>1024) "
    )

    base_stat = (
        " | stats count(*) as count by interfaceId, srcAddr, srcPort, dstAddr, dstPort "
    )
    base_sort = " | sort by count desc "
    base_limit = " | limit 10000 "

    if not dst_addr and not interface_ids and not dst_port:
        print("no query filters were provided....quitting")
        exit()

    ips, enis, ports = None, None, None
    eni_match_ip_string, ip_string, eni_string, port_string = "", "", "", ""
    filter_string = ""
    if interface_ids:
        if matching_interface_ip_with_destaddr_ip:
            interface_ids = interface_ids.split(" ")
            ip_address_of_interface_ids = get_private_ips_for_interface_ids(
                session, interface_ids)
            eni_match_ip_string += " | filter (" + " or ".join([f"(interfaceId = '{interface_id}' and dstAddr = '{ip_address}')" for interface_id,
                                                               ip_address in ip_address_of_interface_ids.items()]) + ") "
        else:
            enis = ["'" + x.strip() + "'" for x in re.split(" |,", interface_ids)]
            eni_string = (
                "| filter interfaceId in [" + ",".join(enis) + "]"
            )

    if dst_addr:
        ips = ["'" + x.strip() + "'" for x in re.split(" |,",
                                                       dst_addr) if isip(x.strip())]
        ip_string = (
            "| filter dstAddr in [" + ",".join(ips) + "]"
        )

    if dst_port:
        ports = [str(x.strip()) for x in re.split(" |,", dst_port)]
        port_string = (
            "| filter dstPort in [" + ",".join(ports) + "]"
        )

    if exclude_src_ports:
        exsports = ports = [str(x.strip()) for x in re.split(
            " |,", exclude_src_ports) if len(str(x.strip())) > 0]
        exsport_string = " and (srcPort not in [" + ",".join(exsports) + "])"

    if ip_string:
        base_filter = base_filter + ip_string
    elif eni_string:
        base_filter = base_filter + eni_string
    elif eni_match_ip_string:
        base_filter = base_filter + eni_match_ip_string

    if port_string:
        base_filter = base_filter + port_string

    if exclude_private_ips_from_source:
        base_filter = (
            base_filter
            + " and ( srcAddr not like /^(?:10|127|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\..*$/ )"
        )

    if exclude_src_ports:
        base_filter = base_filter + exsport_string

    return base_filter + base_stat + base_sort + base_limit
