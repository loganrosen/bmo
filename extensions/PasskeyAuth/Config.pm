# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# This Source Code Form is "Incompatible With Secondary Licenses", as
# defined by the Mozilla Public License, v. 2.0.

package Bugzilla::Extension::PasskeyAuth;

use 5.10.1;
use strict;
use warnings;

use constant NAME => 'PasskeyAuth';

use constant REQUIRED_MODULES => [
  {package => 'CBOR-PP',  module => 'CBOR::PP',  version => '0'},
  {package => 'CryptX',   module => 'CryptX',     version => '0.074'},
];

use constant OPTIONAL_MODULES => [];

__PACKAGE__->NAME;
