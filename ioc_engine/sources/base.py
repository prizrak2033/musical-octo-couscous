"""Abstract base class for IOC sources."""

from __future__ import annotations

import abc
import logging
from typing import List

from ..models import IOC

logger = logging.getLogger(__name__)


class BaseIOCSource(abc.ABC):
    """All IOC sources must implement :meth:`fetch`."""

    #: Human-readable name reported in IOC.source
    name: str = "unknown"

    @abc.abstractmethod
    def fetch(self) -> List[IOC]:
        """Fetch IOCs from this source and return them as a list."""

    def __repr__(self) -> str:  # pragma: no cover
        return f"<{self.__class__.__name__} name={self.name!r}>"
