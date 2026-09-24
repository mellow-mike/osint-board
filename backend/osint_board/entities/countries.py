"""Country names and common aliases → ISO 3166-1 alpha-2, for the country extractor and geo resolution."""

from __future__ import annotations

import re

COUNTRIES: dict[str, str] = {
    "AF": "Afghanistan", "AL": "Albania", "DZ": "Algeria", "AD": "Andorra", "AO": "Angola", "AR": "Argentina",
    "AM": "Armenia", "AU": "Australia", "AT": "Austria", "AZ": "Azerbaijan", "BS": "Bahamas", "BH": "Bahrain",
    "BD": "Bangladesh", "BB": "Barbados", "BY": "Belarus", "BE": "Belgium", "BZ": "Belize", "BJ": "Benin",
    "BT": "Bhutan", "BO": "Bolivia", "BA": "Bosnia and Herzegovina", "BW": "Botswana", "BR": "Brazil",
    "BN": "Brunei", "BG": "Bulgaria", "BF": "Burkina Faso", "BI": "Burundi", "KH": "Cambodia", "CM": "Cameroon",
    "CA": "Canada", "CV": "Cape Verde", "CF": "Central African Republic", "TD": "Chad", "CL": "Chile", "CN": "China",
    "CO": "Colombia", "KM": "Comoros", "CG": "Congo", "CD": "Democratic Republic of the Congo", "CR": "Costa Rica",
    "CI": "Ivory Coast", "HR": "Croatia", "CU": "Cuba", "CY": "Cyprus", "CZ": "Czech Republic", "DK": "Denmark",
    "DJ": "Djibouti", "DM": "Dominica", "DO": "Dominican Republic", "EC": "Ecuador", "EG": "Egypt",
    "SV": "El Salvador", "GQ": "Equatorial Guinea", "ER": "Eritrea", "EE": "Estonia", "SZ": "Eswatini",
    "ET": "Ethiopia", "FJ": "Fiji", "FI": "Finland", "FR": "France", "GA": "Gabon", "GM": "Gambia", "GE": "Georgia",
    "DE": "Germany", "GH": "Ghana", "GR": "Greece", "GD": "Grenada", "GT": "Guatemala", "GN": "Guinea",
    "GW": "Guinea-Bissau", "GY": "Guyana", "HT": "Haiti", "HN": "Honduras", "HK": "Hong Kong", "HU": "Hungary",
    "IS": "Iceland", "IN": "India", "ID": "Indonesia", "IR": "Iran", "IQ": "Iraq", "IE": "Ireland", "IL": "Israel",
    "IT": "Italy", "JM": "Jamaica", "JP": "Japan", "JO": "Jordan", "KZ": "Kazakhstan", "KE": "Kenya",
    "KI": "Kiribati", "KP": "North Korea", "KR": "South Korea", "XK": "Kosovo", "KW": "Kuwait", "KG": "Kyrgyzstan",
    "LA": "Laos", "LV": "Latvia", "LB": "Lebanon", "LS": "Lesotho", "LR": "Liberia", "LY": "Libya",
    "LI": "Liechtenstein", "LT": "Lithuania", "LU": "Luxembourg", "MO": "Macau", "MG": "Madagascar", "MW": "Malawi",
    "MY": "Malaysia", "MV": "Maldives", "ML": "Mali", "MT": "Malta", "MH": "Marshall Islands", "MR": "Mauritania",
    "MU": "Mauritius", "MX": "Mexico", "FM": "Micronesia", "MD": "Moldova", "MC": "Monaco", "MN": "Mongolia",
    "ME": "Montenegro", "MA": "Morocco", "MZ": "Mozambique", "MM": "Myanmar", "NA": "Namibia", "NR": "Nauru",
    "NP": "Nepal", "NL": "Netherlands", "NZ": "New Zealand", "NI": "Nicaragua", "NE": "Niger", "NG": "Nigeria",
    "MK": "North Macedonia", "NO": "Norway", "OM": "Oman", "PK": "Pakistan", "PW": "Palau", "PS": "Palestine",
    "PA": "Panama", "PG": "Papua New Guinea", "PY": "Paraguay", "PE": "Peru", "PH": "Philippines", "PL": "Poland",
    "PT": "Portugal", "PR": "Puerto Rico", "QA": "Qatar", "RO": "Romania", "RU": "Russia", "RW": "Rwanda",
    "KN": "Saint Kitts and Nevis", "LC": "Saint Lucia", "VC": "Saint Vincent and the Grenadines", "WS": "Samoa",
    "SM": "San Marino", "ST": "Sao Tome and Principe", "SA": "Saudi Arabia", "SN": "Senegal", "RS": "Serbia",
    "SC": "Seychelles", "SL": "Sierra Leone", "SG": "Singapore", "SK": "Slovakia", "SI": "Slovenia",
    "SB": "Solomon Islands", "SO": "Somalia", "ZA": "South Africa", "SS": "South Sudan", "ES": "Spain",
    "LK": "Sri Lanka", "SD": "Sudan", "SR": "Suriname", "SE": "Sweden", "CH": "Switzerland", "SY": "Syria",
    "TW": "Taiwan", "TJ": "Tajikistan", "TZ": "Tanzania", "TH": "Thailand", "TL": "Timor-Leste", "TG": "Togo",
    "TO": "Tonga", "TT": "Trinidad and Tobago", "TN": "Tunisia", "TR": "Turkey", "TM": "Turkmenistan",
    "TV": "Tuvalu", "UG": "Uganda", "UA": "Ukraine", "AE": "United Arab Emirates", "GB": "United Kingdom",
    "US": "United States", "UY": "Uruguay", "UZ": "Uzbekistan", "VU": "Vanuatu", "VA": "Vatican City",
    "VE": "Venezuela", "VN": "Vietnam", "YE": "Yemen", "ZM": "Zambia", "ZW": "Zimbabwe",
}  # fmt: skip

ALIASES: dict[str, str] = {
    "usa": "US", "u.s.a.": "US", "u.s.": "US", "united states of america": "US", "america": "US",
    "uk": "GB", "u.k.": "GB", "great britain": "GB", "britain": "GB", "england": "GB", "scotland": "GB",
    "wales": "GB", "northern ireland": "GB", "uae": "AE", "russian federation": "RU", "prc": "CN",
    "people's republic of china": "CN", "republic of korea": "KR", "korea": "KR", "dprk": "KP",
    "czechia": "CZ", "holland": "NL", "the netherlands": "NL", "türkiye": "TR", "turkiye": "TR",
    "cote d'ivoire": "CI", "côte d'ivoire": "CI", "burma": "MM", "swaziland": "SZ", "macedonia": "MK",
    "viet nam": "VN", "iran, islamic republic of": "IR", "syrian arab republic": "SY", "lao": "LA",
    "drc": "CD", "dr congo": "CD", "republic of the congo": "CG", "taiwan, province of china": "TW",
    "hong kong sar": "HK", "vatican": "VA", "holy see": "VA", "east timor": "TL", "cabo verde": "CV",
    "saint kitts": "KN", "st. lucia": "LC", "moldova, republic of": "MD", "bosnia": "BA",
}  # fmt: skip

NAME_TO_CODE: dict[str, str] = {name.lower(): code for code, name in COUNTRIES.items()} | ALIASES

_PATTERN = re.compile(
    r"(?<![A-Za-z])(" + "|".join(re.escape(n) for n in sorted(NAME_TO_CODE, key=len, reverse=True)) + r")(?![A-Za-z])",
    re.I,
)


def country_code(value: str) -> str | None:
    """``'United Kingdom'`` / ``'uk'`` / ``'GB'`` → ``'GB'``."""
    v = value.strip()
    if len(v) == 2 and v.upper() in COUNTRIES:
        return v.upper()
    return NAME_TO_CODE.get(v.lower())


def find_countries(text: str) -> list[tuple[str, str, int]]:
    """``(code, matched text, offset)`` for every country name mentioned, first mention only per country."""
    out: list[tuple[str, str, int]] = []
    seen: set[str] = set()
    for m in _PATTERN.finditer(text):
        code = NAME_TO_CODE[m.group(1).lower()]
        if code in seen:
            continue
        seen.add(code)
        out.append((code, m.group(1), m.start()))
    return out
