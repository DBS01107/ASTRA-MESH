from core.extractors.nmap import NmapExtractor

EXTRACTORS = {
    "nmap": NmapExtractor(),
    # add more later
}

def get_extractor(tool_name: str):
    return EXTRACTORS.get(tool_name)
