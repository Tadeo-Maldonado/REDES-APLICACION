from .cisco import CiscoCollector
from .aruba import ArubaCollector
from .alcatel import AlcatelCollector

COLLECTORS = {
    "cisco": CiscoCollector,
    "aruba": ArubaCollector,
    "alcatel": AlcatelCollector,
}
