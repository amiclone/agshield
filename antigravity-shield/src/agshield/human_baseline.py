"""Human-speed baseline model used by the experimental harness.

The model does not execute anti-forensic commands. It records controlled,
seedable delays representing command entry, observation, and task switching.
This keeps the published defensive package safe while implementing the
qualitative human-baseline protocol described in the dissertation.
"""

import random
import time
from typing import Callable, Dict, Optional


STEPS = (
    ("manual_timestomp", "timestamp verification", 2.0, 5.0),
    ("manual_secure_delete", "secure deletion", 3.0, 6.0),
    ("manual_log_clear", "log clearing", 2.0, 4.0),
    ("manual_service_stop", "monitoring service stop", 2.0, 5.0),
    ("manual_history_clear", "shell history clearing", 1.0, 2.0),
)


def run_human_baseline(
    trial: int,
    seed: Optional[int] = None,
    sleep: Callable[[float], None] = time.sleep,
) -> Dict:
    """Run one reproducible human-speed timing trial.

    ``sleep`` is injectable so the timing model can be tested without waiting.
    The returned planned duration is the primary comparison metric; observed
    duration is retained as an execution-quality check.
    """
    # Non-cryptographic reproducibility is intentional for experimental timing.
    rng = random.Random(seed)  # nosec B311
    actions = []
    started = time.perf_counter()

    for tool, activity, minimum, maximum in STEPS:
        planned_delay = rng.uniform(minimum, maximum)
        step_started = time.perf_counter()
        sleep(planned_delay)
        actions.append(
            {
                "tool": tool,
                "activity": activity,
                "planned_delay_seconds": round(planned_delay, 4),
                "observed_duration_seconds": round(
                    time.perf_counter() - step_started, 4
                ),
            }
        )

    return {
        "trial": trial,
        "mode": "human_baseline",
        "seed": seed,
        "actions": actions,
        "planned_duration_seconds": round(
            sum(action["planned_delay_seconds"] for action in actions), 4
        ),
        "observed_duration_seconds": round(time.perf_counter() - started, 4),
    }
