from dateutil import parser
from datetime import timezone

def date_parser(date_:str, format_str:str):
    parsed_date = parser.parse(date_)
    utc_date = parsed_date.astimezone(timezone.utc)
    new_date = utc_date.strftime(format_str)
    return new_date