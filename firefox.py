import argparse
import json
import os
import sys
from configparser import ConfigParser
from nss import NSSProxy


profile_path = "~/.mozilla/firefox"
DEFAULT_ENCODING = "utf-8"
PWStore = list[dict[str, str]]


class Firefox:
    def __init__(self):
        self.profile = None
        self.proxy = NSSProxy()

    def load_profile(self, profile):
        self.profile = profile
        self.proxy.initialize(self.profile)

    def unload_profile(self):
        self.proxy.shutdown()

    def getCredentialsJson(self):
        db = os.path.join(self.profile, "logins.json")

        if not os.path.isfile(db):
            print("\n[ - ] O usuário não tem senhas salvas: logins.json",
                  file=sys.stderr)
            sys.exit(1)

        with open(db) as fh:
            data = json.load(fh)
            logins = data["logins"]
            for i in logins:
                yield (i["hostname"], i["encryptedUsername"],
                       i["encryptedPassword"], i["encType"])

    def decrypt_passwords(self) -> PWStore:
        credentials = self.getCredentialsJson()

        outputs: list[dict[str, str]] = []

        for url, user, passw, enctype in credentials:
            if enctype:
                try:
                    user = self.proxy.decrypt(user)
                    passw = self.proxy.decrypt(passw)
                except (TypeError, ValueError) as e:
                    continue

            output = {"url": url, "user": user, "password": passw}
            outputs.append(output)

        return outputs

    def printOutput(self, pwstore: PWStore):
        for output in pwstore:
            if output['url'] == 'chrome://FirefoxAccounts':
                continue
            record: str = (
                f"\nWebsite:   {output['url']}\n"
                f"Username: '{output['user']}'\n"
                f"Password: '{output['password']}'"
            )
            print(record)

    def get_sections(self, profiles):
        sections = {}
        i = 1
        for section in profiles.sections():
            if section.startswith("Profile"):
                sections[str(i)] = profiles.get(section, "Path")
                i += 1
            else:
                continue
        return sections

    def read_profiles(self, basepath):
        profileini = os.path.join(basepath, "profiles.ini")

        if not os.path.isfile(profileini):
            print("File not found: profiles.ini", file=sys.stderr)
            sys.exit(1)

        profiles = ConfigParser()
        profiles.read(profileini, encoding=DEFAULT_ENCODING)

        return profiles

    def get_profile(self, basepath: str):
        profiles: ConfigParser = self.read_profiles(basepath)

        sections = self.get_sections(profiles)

        print("Available profiles: ", sections)

        section = sections["1"]
        print("Using profile: ", section)

        section = section
        profile = os.path.join(basepath, section)

        return profile


def main() -> None:
    firefox = Firefox()

    basepath = os.path.expanduser(profile_path)

    profile = firefox.get_profile(basepath)

    firefox.load_profile(profile)

    outputs = firefox.decrypt_passwords()

    firefox.printOutput(outputs)

    firefox.unload_profile()


if __name__ == "__main__":
    main()
