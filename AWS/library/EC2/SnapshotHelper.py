
import logging
import botocore.exceptions


def do_snapshot_delete(resource, asset_id, dry_run):
    """
    Thi function execute delete for single snapshot id
    :param resource: The boto ec2 resource
    :param asset_id: The aws snapshot id
    :param dry_run: Boolean flag to mark if this is dry run or not
    :return:
    """
    logging.info(f"Going to delete snapshot - {asset_id}")
    snapshot = resource.Snapshot(asset_id)
    try:
        response = snapshot.delete(DryRun=dry_run)
    except botocore.exceptions.ClientError as ce:
        if ce.response["Error"]["Code"] == "DryRunOperation":
            logging.warning(
                f"This is a Dry run - operation would have succeeded")


def do_snapshot_ls(session):
    ec2_client = session.client("ec2")
    response = ec2_client.describe_snapshots(OwnerIds=["self"])
    snapshots = set()
    for snapshot in response["Snapshots"]:
        snapshots.add(snapshot["SnapshotId"])
    print(",".join(snapshots))


def do_snapshot_encrypt(session, asset_id, dry_run, kms_key_id=None):
    """
    Thi function handle Snapshot encryption, If EBS default encryption is set, the function will only clone the snapshot
    :param session: boto3 session
    :param asset_id: the snapshot id to encrypt
    :param dry_run: dry run flag
    :return:
    """
    ec2_client = session.client("ec2")
    response_describe = ec2_client.describe_snapshots(SnapshotIds=[asset_id])

    snap = response_describe["Snapshots"][0]
    if snap["Encrypted"]:
        logging.info(
            f"Snapshot {asset_id} is already encrypted, going to skip this execution"
        )

    # response = ec2_client.get_ebs_encryption_by_default()
    # only_clone = response['EbsEncryptionByDefault']
    desc = f"Tamnoon-Automation, encrypted copy for - {asset_id}"

    if kms_key_id:
        response = ec2_client.copy_snapshot(
            Description=desc,
            Encrypted=True,
            KmsKeyId=kms_key_id,
            SourceRegion=session.region_name,
            SourceSnapshotId=asset_id,
        )
    else:
        response = ec2_client.copy_snapshot(
            Description=desc,
            Encrypted=True,
            SourceRegion=session.region_name,
            SourceSnapshotId=asset_id,
        )
    logging.info(f"Snapshot - {asset_id} was encrypted")
