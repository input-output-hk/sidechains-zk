// Constant-time, variable-base scalar multiplication. To comput s * P we use
// the windowed method.
//
// Construct a lookup table of [P,2P,3P,4P,5P,6P,7P,8P]
//
// Compute the 2^3 radix representation of s:
//
//    s = s_0 + s_1 * 8^1 + ... + s_31 * 8^31,
//
// with `0 ≤ s_i < 8` for `0 ≤ i ≤ 31`.
//
// This decomposition requires s < 2^256.
//
// Compute s * P as
//
//    s * P = P * (s_0 +   s_1 * 8^1 +   s_2 * 8^2 + ... +   s_31 * 8^31)
//    s * P = P * s_0 + P * s_1 * 8^1 + P * s_2 * 8^2 + ... + P * s_31 * 8^31
//    s * P = P * s_0 + 8 * (P * s_1 + 8 * (P * s_2 + 8 * ( ... + 8 * P * s_31)...))
//
// We sum right-to-left.
//
// We follow the technique of logic gate configuration for the summed decomposition. The
// lookup is as follows:
// q_mult * [
//    (1 - q_last) * lookup[limb - base * limb_next, x_p, y_p] +
//    q_last * lookup[limb, x_p, y_p]
// ]
//
// Layout
// +---------------------------------------------+
// | q_mult | q_last |  limb |   x_p   |   y_p   |
// +---------------------------------------------+
// |    1   |    0   |   s   | x_p[31] | y_p[31] |
// |    1   |    0   | s[31] | x_p[30] | y_p[30] |
// |    1   |    0   | s[30] | x_p[29] | y_p[29] |
// |   ...  |   ...  |  ...  |   ...   |   ...   |
// |    1   |    0   | s[1]  | x_p[0]  | y_p[0]  |
// |    1   |    1   | s[0]  |    0    |   0     |
// |    0   |    0   |   0   |    0    |   0     |
// +---------------------------------------------+
//
// Once we have the associated multiples, we compute our sum as follows:
//
// +---------------------------------------------------+
// |   x_acc   |   y_acc   |   8_x_acc   |   8_y_acc   |
// +---------------------------------------------------+
// | x_acc[31] | y_acc[31] | 8_x_acc[31] | 8_y_acc[31] |
// | x_acc[30] | y_acc[30] | 8_x_acc[30] | 8_y_acc[30] |
// |    ...    |    ...    |     ...     |     ...     |
// | x_acc[0]  | y_acc[0]  | 8_x_acc[0]  | 8_y_acc[0]  |
// | x_acc     | y_acc     | 8_x_acc     | 8_y_acc     |
// +---------------------------------------------------+
//
// Let
// * sum(x_p, y_p, x_q, y_q, x_r, y_r) constrain that (x_p, y_p) + (x_q, y_q) = (x_r, y_r)
// * double_3(x_p, y_p, x_r, y_r) constrain that [2^3](x_p, y_p) = (x_r, y_r)
//
// We make the following constrains:
// * x_acc[31] = x_p[31];
//
// * y_acc[31] = y_p[31];
//
// * 8_x_acc[i] \
//                } --> double_3(x_acc[i], y_acc[i], 8_x_acc[i], 8_y_acc[i])
// * 8_x_acc[i] /
//
// * x_acc[j] \
//              } --> sum(x_p[j], y_p[j], 8_x_acc[j + 1], 8_y_acc[j + 1], x_acc[j], y_acc[j])
// * y_acc[j] /
//
// for 0 ≤ i ≤ 31 and 0 ≤ j ≤ 30.
//
//
//


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MulConfig {
    // Table columns
    t_limb: TableColumn,
    t_x_out: TableColumn,
    t_y_out: TableColumn,

    q_mul: Selector,

    // x-coordinate of P in a * P = R
    pub x_p: Column<Advice>,
    // y-coordinate of P in a * P = R
    pub y_p: Column<Advice>,
    // scalar a in a * P = R
    pub a: Column<Advice>,
    // x-coordinate of R in a * P = R
    pub x_r: Column<Advice>,
    // y-coordinate of R in a * P = R
    pub y_r: Column<Advice>,
}

impl MulConfig {
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<jubjub::Base>,
        x_p: Column<Advice>,
        y_p: Column<Advice>,
        a: Column<Advice>,
        x_r: Column<Advice>,
        y_r: Column<Advice>,
    ) -> Self {
        let t_limb = meta.lookup_table_column();
        let t_x_out = meta.lookup_table_column();
        let t_y_out = meta.lookup_table_column();

        meta.enable_equality(x_p);
        meta.enable_equality(y_p);
        meta.enable_equality(x_r);
        meta.enable_equality(y_r);

        let config = Self {
            t_limb,
            t_x_out,
            t_y_out,
            q_mul: meta.selector(),
            x_p,
            y_p,
            a,
            x_r,
            y_r
        };

        config.create_gate(meta);

        config
    }

    pub(crate) fn advice_columns(&self) -> HashSet<Column<Advice>> {
        [
            self.x_p,
            self.y_p,
            self.a,
        ]
            .into_iter()
            .collect()
    }

    pub(crate) fn output_columns(&self) -> HashSet<Column<Advice>> {
        [self.x_r, self.y_r].into_iter().collect()
    }


}
