# Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import os
import sys
import time

if __name__ == '__main__':
    realstdout = os.fdopen(os.dup(1), 'w')
    os.dup2(2, 1)  # stderr(2) will be also available in fd 1 (stdout)

    print("Esto va a stderr")
    time.sleep(2)
    print("Esto va a stoudt", file=realstdout)
