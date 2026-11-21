package com.github.auties00.parley.media;

import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/// The H.264 profile and level a `profile-level-id` format parameter names.
///
/// The parameter is three bytes in hexadecimal: `profile_idc`, `profile-iop` (the constraint flags) and `level_idc`.
/// Several byte combinations name the same profile (Constrained Baseline is `42e0`, `4d80` or `58c0`), so two codecs
/// are compared by [#profile()], never by the hexadecimal text.
///
/// @param profile the profile
/// @param level   the level
/// @spec https://www.rfc-editor.org/rfc/rfc6184.html RFC 6184: RTP Payload Format for H.264 Video
/// @spec https://www.itu.int/rec/T-REC-H.264 ITU-T H.264: Advanced video coding for generic audiovisual services
public record H264ProfileLevelId(Profile profile, Level level) {
    /// The `constraint_set3_flag` bit of `profile-iop`, which turns level `1.1` into level `1b`.
    private static final int CONSTRAINT_SET3_FLAG = 0x10;

    /// The profile and level a codec without a `profile-level-id` parameter is taken to use.
    ///
    /// @implNote This implementation uses Constrained Baseline level 3.1, as browsers do, rather than the Baseline
    /// level 1.0 of RFC 6184: the absent parameter then matches the profile every browser offers first.
    public static final H264ProfileLevelId DEFAULT = new H264ProfileLevelId(Profile.CONSTRAINED_BASELINE, Level.LEVEL_3_1);

    /// Creates a profile and level.
    ///
    /// @param profile the profile
    /// @param level   the level
    public H264ProfileLevelId {
        Objects.requireNonNull(profile, "profile cannot be null");
        Objects.requireNonNull(level, "level cannot be null");
    }

    /// Parses a `profile-level-id` value.
    ///
    /// @param value six hexadecimal digits in either case
    /// @return the profile and level, or an empty optional if `value` is malformed or names a profile or level this
    ///         class does not know
    public static Optional<H264ProfileLevelId> parse(String value) {
        if (value.length() != 6 || !value.chars().allMatch(c -> Character.digit(c, 16) >= 0)) {
            return Optional.empty();
        }
        var bytes = HexFormat.of().parseHex(value.toLowerCase(Locale.ROOT));
        var profileIdc = bytes[0] & 0xFF;
        var profileIop = bytes[1] & 0xFF;
        var levelIdc = bytes[2] & 0xFF;
        var level = levelIdc == 11 && (profileIop & CONSTRAINT_SET3_FLAG) != 0
                ? Optional.of(Level.LEVEL_1B)
                : Level.ofIdc(levelIdc);
        if (level.isEmpty()) {
            return Optional.empty();
        }
        for (var pattern : Profile.PATTERNS) {
            if (pattern.matches(profileIdc, profileIop)) {
                return Optional.of(new H264ProfileLevelId(pattern.profile(), level.get()));
            }
        }
        return Optional.empty();
    }

    /// {@return the profile and level of a codec's format parameters, [#DEFAULT] when they have no
    /// `profile-level-id`, or an empty optional when the parameter is malformed}
    ///
    /// @param formatParameters the `a=fmtp` parameters, keys in lower case
    public static Optional<H264ProfileLevelId> of(Map<String, String> formatParameters) {
        var value = formatParameters.get("profile-level-id");
        return value == null ? Optional.of(DEFAULT) : parse(value);
    }

    /// {@return the `profile-level-id` value, six lower-case hexadecimal digits}
    ///
    /// Level 1b is written as `level_idc` 11 with `constraint_set3_flag` for the Baseline and Main profiles, and as
    /// `level_idc` 9 for the others.
    @Override
    public String toString() {
        if (level == Level.LEVEL_1B) {
            switch (profile) {
                case CONSTRAINED_BASELINE -> {
                    return "42f00b";
                }
                case BASELINE -> {
                    return "42100b";
                }
                case MAIN -> {
                    return "4d100b";
                }
                default -> {
                }
            }
        }
        var prefix = switch (profile) {
            case CONSTRAINED_BASELINE -> "42e0";
            case BASELINE -> "4200";
            case MAIN -> "4d00";
            case CONSTRAINED_HIGH -> "640c";
            case HIGH -> "6400";
            case PREDICTIVE_HIGH_444 -> "f400";
        };
        return prefix + HexFormat.of().toHexDigits((byte) (level == Level.LEVEL_1B ? 9 : level.idc()));
    }

    /// The H.264 profiles WebRTC negotiates.
    public enum Profile {
        /// Constrained Baseline, the profile every WebRTC endpoint supports.
        CONSTRAINED_BASELINE,

        /// Baseline.
        BASELINE,

        /// Main.
        MAIN,

        /// Constrained High.
        CONSTRAINED_HIGH,

        /// High.
        HIGH,

        /// Predictive High 4:4:4.
        PREDICTIVE_HIGH_444;

        /// The byte patterns of each profile, in the order they are tried.
        private static final ProfilePattern[] PATTERNS = {
                new ProfilePattern(0x42, "x1xx0000", CONSTRAINED_BASELINE),
                new ProfilePattern(0x4D, "1xxx0000", CONSTRAINED_BASELINE),
                new ProfilePattern(0x58, "11xx0000", CONSTRAINED_BASELINE),
                new ProfilePattern(0x42, "x0xx0000", BASELINE),
                new ProfilePattern(0x58, "10xx0000", BASELINE),
                new ProfilePattern(0x4D, "0x0x0000", MAIN),
                new ProfilePattern(0x64, "00000000", HIGH),
                new ProfilePattern(0x64, "00001100", CONSTRAINED_HIGH),
                new ProfilePattern(0xF4, "00000000", PREDICTIVE_HIGH_444)
        };
    }

    /// The H.264 levels, in increasing order of capability.
    public enum Level {
        /// Level 1.
        LEVEL_1(10),
        /// Level 1b, between levels 1 and 1.1.
        LEVEL_1B(0),
        /// Level 1.1.
        LEVEL_1_1(11),
        /// Level 1.2.
        LEVEL_1_2(12),
        /// Level 1.3.
        LEVEL_1_3(13),
        /// Level 2.
        LEVEL_2(20),
        /// Level 2.1.
        LEVEL_2_1(21),
        /// Level 2.2.
        LEVEL_2_2(22),
        /// Level 3.
        LEVEL_3(30),
        /// Level 3.1.
        LEVEL_3_1(31),
        /// Level 3.2.
        LEVEL_3_2(32),
        /// Level 4.
        LEVEL_4(40),
        /// Level 4.1.
        LEVEL_4_1(41),
        /// Level 4.2.
        LEVEL_4_2(42),
        /// Level 5.
        LEVEL_5(50),
        /// Level 5.1.
        LEVEL_5_1(51),
        /// Level 5.2.
        LEVEL_5_2(52),
        /// Level 6.
        LEVEL_6(60),
        /// Level 6.1.
        LEVEL_6_1(61),
        /// Level 6.2.
        LEVEL_6_2(62);

        /// The `level_idc`, `0` for level 1b, which has none of its own.
        private final int idc;

        Level(int idc) {
            this.idc = idc;
        }

        /// {@return the `level_idc` of the level; `11` for level 1b, which sets `constraint_set3_flag` instead}
        public int idc() {
            return this == LEVEL_1B ? 11 : idc;
        }

        /// {@return the level of a `level_idc`; `9`, the High profiles' code for level 1b, is level 1b}
        ///
        /// @param idc the `level_idc`
        static Optional<Level> ofIdc(int idc) {
            if (idc == 9) {
                return Optional.of(LEVEL_1B);
            }
            for (var level : values()) {
                if (level.idc == idc && level != LEVEL_1B) {
                    return Optional.of(level);
                }
            }
            return Optional.empty();
        }
    }

    /// One `profile_idc` and `profile-iop` pattern of a profile.
    ///
    /// @param profileIdc the `profile_idc`
    /// @param iopPattern the eight bits of `profile-iop`, most significant first, `x` for any value
    /// @param profile    the profile the pattern names
    private record ProfilePattern(int profileIdc, String iopPattern, Profile profile) {
        /// {@return whether a `profile_idc` and `profile-iop` match the pattern}
        boolean matches(int idc, int iop) {
            if (idc != profileIdc) {
                return false;
            }
            for (var i = 0; i < 8; i++) {
                var expected = iopPattern.charAt(i);
                var bit = (iop >>> (7 - i)) & 1;
                if (expected != 'x' && expected - '0' != bit) {
                    return false;
                }
            }
            return true;
        }
    }
}
