from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Any, List, Optional

import botocore

@dataclass
class ModuleResult:
    name: str
    status: str
    message: str
    count: int = 0
    findings: List[Any] = None

def run_module(name: str, fn: Callable[[], List[Any]]) -> ModuleResult:
    """
    Launch module and return normalized result
    - ok : success , count = len(findings)
    - skipped : don't enoght permission (AsseccDenied/Unauthorized)
    - info : module is not realised (NotImplementError) or empty
    - error : anything else
    """
    try:
        findings = fn()
        cnt = len(findings)

        # "Empty" - thats not mean error
        if cnt == 0:
            return ModuleResult(name=name, status="info", message="no findings", count=0, findings=[])

        return ModuleResult(name=name, status="ok", message=f"found {cnt}", count=cnt, findings=findings)

    except NotImplementedError:
        return ModuleResult(name=name, status="skipped", message="not implemented yet", count=0,findings=[])

    except botocore.exceptions.ClientError as e:
        code = e.response.get("Error", {}).get("Code", "Unknown")
        if code == "AWSOrganizationsNotInUseException":
            return ModuleResult(name=name, status="info", message="orginizations not in use", count = 0, findings=[])

        if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
            return ModuleResult(name=name, status="skipped", message=f"missing permission ({code})", count=0, findings=[])
        return ModuleResult(name=name,status="error", message=f"AWS error ({code})", count=0, findings=[])

    except Exception as e:
        return ModuleResult(name=name, status="error", message=f"{type(e).__name__}: {e}", count=0, findings=[])