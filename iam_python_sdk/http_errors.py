# Copyright 2022 AccelByte Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


# Error name = HTTP code, Error code, Message
UnauthorizedAccess = 401, 20001, "unauthorized access"
InvalidRefererHeader = 401, 20023, "invalid referer header"
InsufficientPermissions = 403, 20013, "insufficient permissions"
SubdomainMismatch = 404, 20030, "subdomain mismatch error"
InternalServerError = 500, 20000, "internal server error"
