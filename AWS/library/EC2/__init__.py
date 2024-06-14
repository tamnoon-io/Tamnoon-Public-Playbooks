"""
initialize module EC2Actions
"""
import os
import sys

___DIRECTORY_DEPTH = 2
___RELATIVE_PATH = "TamnoonPlaybooks/AWS/"

___splits = sys.path[0].split("/")
___import_path = os.path.join(
    "/".join(___splits[0 : len(___splits) - ___DIRECTORY_DEPTH]), ___RELATIVE_PATH
)
sys.path.append(___import_path)
