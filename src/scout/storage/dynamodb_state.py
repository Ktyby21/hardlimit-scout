from __future__ import annotations

from typing import Dict, Optional
import boto3

class DynamoDbStateStore:
    """
    Stores 'last sent threshold' per finding (fid) for a given account_id.
    Table schema: pk (S), sk(S)
        pk = account_id
        sk = fid
        last_threshold (N)
    """
    def __init__(self, session: boto3.Session, table_name: str):
        self.ddb = session.client("dynamodb")
        self.table = table_name

    def load_last_sent(self, account_id:str) -> Dict[str, float]:

        out: Dict[str, float] = {}
        start_key: Optional[dict] = None
        
        while True:
            kwargs = dict(
                TableName=self.table,
                KeyConditionExpression="pk = :pk",
                ExpressionAttributeValues={":pk": {"S":account_id}},
                ConsistentRead=True,
            )
            if start_key:
                kwargs["ExclusiveStartKey"] = start_key
            
            resp = self.ddb.query(**kwargs)

            for it in resp.get("Items", []):
                fid = it["sk"]["S"]
                last = float(it.get("last_threshold", {"N": "0"})["N"])
                out[fid] = last
            start_key = resp.get("LastEvaluatedKey")
            if not start_key:
                break
        
        return out


    def save_last_sent(self,account_id:str, data: Dict[str, float]) -> None:
        for fid, threshold in data.items():
            self.ddb.put_item(
                TableName=self.table,
                Item={
                    "pk": {"S": account_id},
                    "sk": {"S": fid},
                    "last_threshold": {"N": str(float(threshold))},
                },
            )