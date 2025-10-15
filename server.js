// src/server/index.js

const express = require('express');
const cors = require("cors");
const db = require('./db'); // This now imports the mysql2 pool
const { google } = require("googleapis");
const nodemailer = require("nodemailer");
const app = express();
app.use(cors());
app.use(express.json());


const allowedOrigins = [
  "https://av-datalibrary-frontend.vercel.app", // Your frontend domain
  "http://localhost:3000",  // Add this for local development
];

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true, // Allow cookies if needed
  })
);

const oAuth2Client = new google.auth.OAuth2(
  process.env.CLIENT_ID,
  process.env.CLIENT_SECRET,
  "https://developers.google.com/oauthplayground"
);
oAuth2Client.setCredentials({ refresh_token: process.env.REFRESH_TOKEN });

async function sendInvitationEmail({ email, role, teams, message, appLink }) {
  const accessToken = await oAuth2Client.getAccessToken();
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      type: "OAuth2",
      user: process.env.EMAIL_USER,
      clientId: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      refreshToken: process.env.REFRESH_TOKEN,
      accessToken: accessToken.token,
    },
  });

  const mailOptions = {
    from: `"AV Data Library" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: "You're Invited!",
    text: `Role: ${role}\nTeams: ${teams.join(", ")}\nMessage: ${message}\nApp Link: ${appLink}`,
    html: `
      <p><strong>Role:</strong> ${role}</p>
      <p><strong>Teams:</strong> ${teams.join(", ")}</p>
      <p><strong>Message:</strong> ${message}</p>
      <p><a href="${appLink}">Join the app</a></p>
    `,
  };

  return transporter.sendMail(mailOptions);
}

app.post('/send-invitation', async (req, res) => {
  const { email, role, teams, message, appLink } = req.body;
  try {
    await sendInvitationEmail({ email, role, teams, message, appLink });
    res.status(200).json({ message: "Invitation sent successfully" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

require('dotenv').config();




// ✅ UPGRADED: This function translates API parameters (start_date) to database columns (FromDate)
// It uses DATE() for robust, timezone-agnostic comparisons.
// ✅ Refactored buildWhereClause (no start_date / end_date filter)
// src/server/index.js


// ✅ REPLACEMENT for your buildWhereClause function
const buildWhereClause = (queryParams, searchFields = [], allColumns = [], tableAliases = {}) => {
    const allowedOperators = {
        'contains': 'LIKE', 'not_contains': 'NOT LIKE', 'equals': '=', 'not_equals': '!=',
        'starts_with': 'LIKE', 'ends_with': 'LIKE', 'in': 'IN', 'not_in': 'NOT IN',
        'greater': '>', 'greater_equal': '>=', 'less': '<', 'less_equal': '<=',
        'is_empty': 'IS_EMPTY', 'is_not_empty': 'IS_NOT_EMPTY', 'between': 'BETWEEN',
    };

    const { page, limit, sortBy, sortDirection, search, advanced_filters, ...filters } = queryParams;
    const whereClauses = [];
    let params = [];

    // --- Helper to get prefixed field name ---
    const getPrefixedField = (field) => {
        const alias = tableAliases[field];
        // If an alias is defined for the field, use it. Otherwise, just escape the field.
        return alias ? `${db.escapeId(alias)}.${db.escapeId(field)}` : db.escapeId(field);
    };

    // --- 1. Handle Global Search ---
    if (search && searchFields.length > 0) {
        const searchConditions = searchFields
            .map(field => `${getPrefixedField(field)} LIKE ?`)
            .join(' OR ');
        whereClauses.push(`(${searchConditions})`);
        params.push(...searchFields.map(() => `%${search}%`));
    }

    // --- 2. Handle Simple Key-Value Filters ---
    Object.keys(filters).forEach(key => {
        const filterValue = queryParams[key];
        const fieldName = key.replace(/_min|_max$/, '');
        if (allColumns.length > 0 && !allColumns.includes(fieldName)) return;
        
        const prefixedField = getPrefixedField(fieldName);

        if (key.endsWith('_min')) {
            whereClauses.push(`${prefixedField} >= ?`);
            params.push(filterValue);
        } else if (key.endsWith('_max')) {
            whereClauses.push(`${prefixedField} <= ?`);
            params.push(filterValue);
        } else if (typeof filterValue === 'string' && filterValue.trim() !== '' && filterValue !== 'all') {
            whereClauses.push(`${prefixedField} = ?`);
            params.push(filterValue);
        }
    });

    // --- 3. Handle Advanced Filters JSON ---
    if (advanced_filters) {
        try {
            const filterGroups = JSON.parse(advanced_filters);
            if (Array.isArray(filterGroups) && filterGroups.length > 0) {
                const groupSqlParts = [];
                filterGroups.forEach((group, groupIndex) => {
                    if (!group.rules || group.rules.length === 0) return;
                    const ruleSqlParts = [];
                    const groupParams = [];

                    group.rules.forEach((rule, ruleIndex) => {
                        const operatorKey = String(rule.operator).toLowerCase();
                        if (!rule.field || !operatorKey || !allColumns.includes(rule.field) || !allowedOperators[operatorKey]) return;
                        
                        const field = getPrefixedField(rule.field);
                        const dbOperator = allowedOperators[operatorKey];
                        let ruleClause = null;
                        const ruleParams = [];

                        switch (dbOperator) {
                            case 'IS_EMPTY': ruleClause = `(${field} IS NULL OR ${field} = '')`; break;
                            case 'IS_NOT_EMPTY': ruleClause = `(${field} IS NOT NULL AND ${field} <> '')`; break;
                            case 'BETWEEN':
                                if (Array.isArray(rule.value) && rule.value.length === 2) {
                                    ruleParams.push(rule.value[0], rule.value[1]);
                                    ruleClause = `${field} BETWEEN ? AND ?`;
                                }
                                break;
                            case 'IN': case 'NOT IN':
                                const inValues = Array.isArray(rule.value) ? rule.value : [rule.value];
                                if (inValues.length > 0) {
                                    ruleParams.push(...inValues);
                                    ruleClause = `${field} ${dbOperator} (${inValues.map(() => '?').join(',')})`;
                                }
                                break;
                            case 'LIKE': case 'NOT LIKE':
                                let paramValue = `%${rule.value}%`;
                                if (operatorKey === 'starts_with') paramValue = `${rule.value}%`;
                                if (operatorKey === 'ends_with') paramValue = `%${rule.value}`;
                                ruleParams.push(paramValue);
                                ruleClause = `${field} ${dbOperator} ?`;
                                break;
                            default:
                                ruleParams.push(rule.value);
                                ruleClause = `${field} ${dbOperator} ?`;
                                break;
                        }

                        if (ruleClause) {
                            if (ruleIndex > 0) ruleSqlParts.push(rule.logic || 'AND');
                            ruleSqlParts.push(ruleClause);
                            groupParams.push(...ruleParams);
                        }
                    });

                    if (ruleSqlParts.length > 0) {
                        const groupClause = `(${ruleSqlParts.join(' ')})`;
                        if (groupIndex > 0) groupSqlParts.push(group.logic || 'OR');
                        groupSqlParts.push(groupClause);
                        params.push(...groupParams);
                    }
                });

                if (groupSqlParts.length > 0) whereClauses.push(`(${groupSqlParts.join(' ')})`);
            }
        } catch (e) {
            console.error("❌ Failed to parse advanced_filters:", e);
        }
    }

    return {
        whereString: whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '',
        params
    };
};


// ✅ REPLACEMENT for your buildOrderByClause function
const buildOrderByClause = (queryParams, allowedColumns = [], tableAliases = {}, dateColumns = []) => {
  let { sortBy, sortDirection } = queryParams;
  const direction = (String(sortDirection).toUpperCase() === 'DESC') ? 'DESC' : 'ASC';

  if (sortBy && allowedColumns.includes(sortBy)) {
    const alias = tableAliases[sortBy];
    const prefixedSortBy = alias
      ? `${db.escapeId(alias)}.${db.escapeId(sortBy)}`
      : db.escapeId(sortBy);

    // If this is a date column, use STR_TO_DATE for correct sorting
    if (dateColumns.includes(sortBy)) {
      // Adjust the format string if your date format is different!
      return `ORDER BY STR_TO_DATE(${prefixedSortBy}, '%d-%m-%Y') ${direction}`;
    }

    // Otherwise, normal sort
    return `ORDER BY ${prefixedSortBy} ${direction}`;
  }

  return '';
};



// --- Events Endpoint ---
// --- Events Endpoint ---
app.get('/api/events', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;

    // Normalize dates (force YYYY-MM-DD)
    function normalizeDate(d) {
      return d ? new Date(d).toISOString().slice(0, 10) : null;
    }
    req.query.start_date = normalizeDate(req.query.start_date);
    req.query.end_date = normalizeDate(req.query.end_date);

    const filterableColumns = [
      'EventID','EventCode','Yr','SubmittedDate','FromDate','ToDate',
      'EventName','fkEventCategory','NewEventCategory','EventRemarks','EventMonth','CommonId',
      'IsSubEvent1','IsAudioRecorded','PravachanCount','UdhgoshCount',
      'PaglaCount','PratisthaCount','SummaryRemarks','Pra-SU-duration',
      'LastModifiedBy','LastModifiedTimestamp','NewEventFrom','NewEventTo'
    ];

    const { whereString, params } = buildWhereClause(
      req.query,
      ['EventID','EventCode','Yr','SubmittedDate','FromDate','ToDate',
      'EventName','fkEventCategory','EventRemarks','EventMonth','CommonId',
      'IsSubEvent1','IsAudioRecorded','PravachanCount','UdhgoshCount',
      'PaglaCount','PratisthaCount','SummaryRemarks','Pra-SU-duration',
      'LastModifiedBy','LastModifiedTimestamp','NewEventFrom','NewEventTo'], // searchable fields
      filterableColumns
    );

    const orderByString = buildOrderByClause(req.query, filterableColumns);

    // --- Count Query ---
    const countQuery = `SELECT COUNT(*) as total FROM Events ${whereString}`;
    const [[{ total }]] = await db.query(countQuery, params);
    const totalPages = Math.ceil(total / limit);

    // --- Data Query ---
    const dataQuery = `SELECT * FROM Events ${whereString} ${orderByString} LIMIT ? OFFSET ?`;
    const [results] = await db.query(dataQuery, [...params, limit, offset]);

    res.json({
      data: results,
      pagination: {
        page,
        limit,
        totalItems: total,
        totalPages
      }
    });
  } catch (err) {
    console.error("❌ DB Error:", err);
    res.status(500).json({ error: 'Database query failed' });
  }
});


app.get('/api/events/export', async (req, res) => {
  try {
    // FIX: Call the generic buildWhereClause function
    const { whereString, params } = buildWhereClause(req.query, ['EventCode', 'EventName', 'Yr'], ['EventID', 'EventCode', 'Yr','SubmittedDate','FromDate','ToDate', 'EventName','fkEventCategory','EventsRemarks','EventMonth','CommonId','IsSubEvent1','IsAudioRecorded','PravachanCount','UdhgoshCount','PaglaCount','PratisthaCount','SummaryRemarks','Pra-SU-duration','LastModifiedBy','LastModifiedTimestamp','NewEventFrom','NewEventTo' /* add more... */]);
    const dataQuery = `SELECT * FROM Events ${whereString}`;
    const [results] = await db.query(dataQuery, params);

    if (results.length === 0) {
      return res.status(404).send("No data found to export for the given filters.");
    }

    const headers = Object.keys(results[0]);
    const csvHeader = headers.join(',');
    const csvRows = results.map(row => headers.map(header => {
        const value = row[header];
        const strValue = String(value === null || value === undefined ? '' : value);
        return `"${strValue.replace(/"/g, '""')}"`;
    }).join(','));
    const csvContent = [csvHeader, ...csvRows].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="events_export.csv"');
    res.status(200).send(csvContent);

  } catch (err) {
    console.error("Database query error on /api/users/export:", err);
    res.status(500).json({ error: 'CSV export failed' });
  }
});


app.put('/api/events/:EventID', async (req, res) => {
  const { EventID } = req.params;
  // Destructure all editable fields from the request body
  const {
    EventCode, Yr, SubmittedDate, FromDate, ToDate, EventName, fkEventCategory,
    NewEventCategory, EventRemarks, EventMonth, CommonID, IsSubEvent1, IsAudioRecorded,
    PravachanCount, UdgoshCount, PaglaCount, PratishthaCount, SummaryRemarks,
    'Pra-SU-duration': PraSUDuration, LastModifiedBy, NewEventFrom, NewEventTo
  } = req.body;

  if (!EventID) {
    return res.status(400).json({ error: "EventID is required." });
  }

  // You can add more validation for required fields if needed

  try {
    const query = `
      UPDATE Events
      SET
        EventCode = ?,
        Yr = ?,
        SubmittedDate = ?,
        FromDate = ?,
        ToDate = ?,
        EventName = ?,
        fkEventCategory = ?,
        NewEventCategory = ?,
        EventRemarks = ?,
        EventMonth = ?,
        CommonID = ?,
        IsSubEvent1 = ?,
        IsAudioRecorded = ?,
        PravachanCount = ?,
        UdgoshCount = ?,
        PaglaCount = ?,
        PratishthaCount = ?,
        SummaryRemarks = ?,
        \`Pra-SU-duration\` = ?,
        LastModifiedBy = ?,
        LastModifiedTimestamp = NOW(),
        NewEventFrom = ?,
        NewEventTo = ?
      WHERE EventID = ?
    `;

    const [result] = await db.query(query, [
      EventCode, Yr, SubmittedDate, FromDate, ToDate, EventName, fkEventCategory,
      NewEventCategory, EventRemarks, EventMonth, CommonID, IsSubEvent1, IsAudioRecorded,
      PravachanCount, UdgoshCount, PaglaCount, PratishthaCount, SummaryRemarks,
      PraSUDuration, LastModifiedBy || '', NewEventFrom, NewEventTo, EventID
    ]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: `Event with ID ${EventID} not found.` });
    }

    res.status(200).json({ message: "Event updated successfully." });
  } catch (err) {
    console.error("❌ Database query error on /api/events/:EventID:", err);
    res.status(500).json({ error: "Failed to update Event." });
  }
});



// --- NewMediaLog Endpoints ---
app.get('/api/newmedialog', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;

    const filterableColumns = [
      'MLUniqueID','FootageSrNo', 'LogSerialNo','fkDigitalRecordingCode','ContentFrom','ContentTo',
      'TimeOfDay','fkOccasion','EditingStatus','FootageType','VideoDistribution','Detail','SubDetail',
      'CounterFrom','CounterTo','SubDuration','TotalDuration','Language','SpeakerSinger','fkOrganization',
      'Designation','fkCountry','fkState','fkCity','Venue','fkGranth','Number','Topic','Seriesname',
      'SatsangStart','SatsangEnd','IsAudioRecorded','AudioMP3Distribution','AudioWAVDistribution',
      'AudioMP3DRCode','AudioWAVDRCode','Remarks','IsStartPage','EndPage','IsInformal','IsPPGNotPresent',
      'Guidance','DiskMasterDuration','EventRefRemarksCounters','EventRefMLID','EventRefMLID2',
      'DubbedLanguage','DubbingArtist','HasSubtitle','SubTitlesLanguage','EditingDeptRemarks','EditingType',
      'BhajanType','IsDubbed','NumberSource','TopicSource','LastModifiedTimestamp','LastModifiedBy',
      'Synopsis','LocationWithinAshram','Keywords','Grading','Segment Category','Segment Duration',
      'TopicGivenBy'
    ];

    const { whereString, params } = buildWhereClause(
      req.query,
      [ 'MLUniqueID','FootageSrNo', 'LogSerialNo','fkDigitalRecordingCode','ContentFrom','ContentTo',
      'TimeOfDay','fkOccasion','EditingStatus','FootageType','VideoDistribution','Detail','SubDetail',
      'CounterFrom','CounterTo','SubDuration','TotalDuration','Language','SpeakerSinger','fkOrganization',
      'Designation','fkCountry','fkState','fkCity','Venue','fkGranth','Number','Topic','Seriesname',
      'SatsangStart','SatsangEnd','IsAudioRecorded','AudioMP3Distribution','AudioWAVDistribution',
      'AudioMP3DRCode','AudioWAVDRCode','Remarks','IsStartPage','EndPage','IsInformal','IsPPGNotPresent',
      'Guidance','DiskMasterDuration','EventRefRemarksCounters','EventRefMLID','EventRefMLID2',
      'DubbedLanguage','DubbingArtist','HasSubtitle','SubTitlesLanguage','EditingDeptRemarks','EditingType',
      'BhajanType','IsDubbed','NumberSource','TopicSource','LastModifiedTimestamp','LastModifiedBy',
      'Synopsis','LocationWithinAshram','Keywords','Grading','Segment Category','Segment Duration',
      'TopicGivenBy'], // global search fields
      filterableColumns
    );

    const orderByString = buildOrderByClause(req.query, filterableColumns);

    // --- Count Query ---
    const countQuery = `SELECT COUNT(*) as total FROM NewMediaLog ${whereString}`;
    const [[{ total }]] = await db.query(countQuery, params);
    const totalPages = Math.ceil(total / limit);

    // --- Data Query ---
    const dataQuery = `
      SELECT * 
      FROM NewMediaLog 
      ${whereString} 
      ${orderByString} 
      LIMIT ? OFFSET ?
    `;
    const [results] = await db.query(dataQuery, [...params, limit, offset]);

    res.json({
      data: results,
      pagination: {
        page,
        limit,
        totalItems: total,
        totalPages
      }
    });
  } catch (err) {
    console.error("❌ Database query error on /api/newmedialog:", err);
    res.status(500).json({ error: 'Database query failed' });
  }
});


// server.js

// ...existing code...
// server.js

app.get('/api/newmedialog/all-except-satsang', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;

    const filterableColumns = [
      'MLUniqueID','FootageSrNo','LogSerialNo','fkDigitalRecordingCode','ContentFrom','ContentTo',
      'TimeOfDay','fkOccasion','EditingStatus','FootageType','VideoDistribution','Detail','SubDetail',
      'CounterFrom','CounterTo','SubDuration','TotalDuration','Language','SpeakerSinger','fkOrganization',
      'Designation','fkCountry','fkState','fkCity','Venue','fkGranth','Number','Topic','Seriesname',
      'SatsangStart','SatsangEnd','IsAudioRecorded','AudioMP3Distribution','AudioWAVDistribution',
      'AudioMP3DRCode','AudioWAVDRCode','Remarks','IsStartPage','EndPage','IsInformal','IsPPGNotPresent',
      'Guidance','DiskMasterDuration','EventRefRemarksCounters','EventRefMLID','EventRefMLID2',
      'DubbedLanguage','DubbingArtist','HasSubtitle','SubTitlesLanguage','EditingDeptRemarks','EditingType',
      'BhajanType','IsDubbed','NumberSource','TopicSource','LastModifiedTimestamp','LastModifiedBy',
      'Synopsis','LocationWithinAshram','Keywords','Grading','Segment Category','Segment Duration','TopicgivenBy',
      // Columns from the 'dr' (DigitalRecordings) table
      'PreservationStatus', 'RecordingCode', 'RecordingName', 'fkEventCode'
    ];

    // --- MODIFICATION: Define table aliases for ambiguous columns ---
    const aliases = {
      'IsInformal': 'nml',
      'PreservationStatus': 'dr',
      'RecordingCode': 'dr',
      'RecordingName': 'dr',
      'fkEventCode': 'dr',
      'LastModifiedTimestamp': 'nml'
    };

    // --- MODIFICATION: Call helpers with plain column names and the aliases map ---
    const { whereString: dynamicWhere, params: dynamicParams } = buildWhereClause(req.query, filterableColumns, filterableColumns, aliases);
    const orderByString = buildOrderByClause(req.query, filterableColumns, aliases) || 'ORDER BY nml.MLUniqueID DESC';
    // --- Static filters specific to this route ---
    const staticWhere = `
      nml.\`Segment Category\` NOT IN (
        'Prasangik Udbodhan', 'SU', 'SU - GM', 'SU - Revision', 
        'Satsang', 'Informal Satsang', 'SU - Extracted'
      )
      AND (
        dr.PreservationStatus IS NULL
        OR TRIM(dr.PreservationStatus) = ''
        OR UPPER(TRIM(dr.PreservationStatus)) = 'PRESERVE'
      )
      AND (
        nml.\`IsInformal\` IS NULL
        OR TRIM(nml.\`IsInformal\`) = ''
        OR UPPER(TRIM(nml.\`IsInformal\`)) = 'NO'
      )
    `;

    // --- Combine dynamic + static filters ---
    const finalWhere = dynamicWhere
      ? `${dynamicWhere} AND (${staticWhere})`
      : `WHERE ${staticWhere}`;
    const finalParams = [...dynamicParams];

    // --- Count query for pagination ---
    const countQuery = `
      SELECT COUNT(*) as total
      FROM NewMediaLog AS nml
      LEFT JOIN DigitalRecordings AS dr 
        ON nml.fkDigitalRecordingCode = dr.RecordingCode
      ${finalWhere}
    `;
    const [[{ total }]] = await db.query(countQuery, finalParams);
    const totalPages = Math.ceil(total / limit);

    // --- Main data query ---
    const dataQuery = `
      SELECT 
        nml.*,
        dr.PreservationStatus,
        dr.RecordingCode,
        dr.RecordingName,
        dr.fkEventCode
      FROM NewMediaLog AS nml
      LEFT JOIN DigitalRecordings AS dr 
        ON nml.fkDigitalRecordingCode = dr.RecordingCode
      ${finalWhere}
      ${orderByString}
      LIMIT ? OFFSET ?
    `;

    const [rows] = await db.query(dataQuery, [...finalParams, limit, offset]);

    // --- Response ---
    res.json({
      data: rows,
      pagination: {
        page,
        limit,
        totalItems: total,
        totalPages
      }
    });
  } catch (err) {
    console.error("❌ API Error for /api/newmedialog/all-except-satsang:", err);
    res.status(500).json({ error: err.message });
  }
});



// --- Corrected Endpoint for "Satsang Extracted Clips" (Using your query) ---
// ...existing code...

// --- Corrected Endpoint for "Satsang Extracted Clips" (Using your query) ---
// ...existing code...
// --- Corrected Endpoint for "Satsang Extracted Clips" (Using your query) ---
app.get('/api/newmedialog/satsang-extracted-clips', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;

    const filterableColumns = [
      'MLUniqueID','FootageSrNo', 'LogSerialNo','fkDigitalRecordingCode','ContentFrom','ContentTo',
      'TimeOfDay','fkOccasion','EditingStatus','FootageType','VideoDistribution','Detail','SubDetail',
      'CounterFrom','CounterTo','SubDuration','TotalDuration','Language','SpeakerSinger','fkOrganization',
      'Designation','fkCountry','fkState','fkCity','Venue','fkGranth','Number','Topic','Seriesname',
      'SatsangStart','SatsangEnd','IsAudioRecorded','AudioMP3Distribution','AudioWAVDistribution',
      'AudioMP3DRCode','AudioWAVDRCode','Remarks','IsStartPage','EndPage','IsInformal','IsPPGNotPresent',
      'Guidance','DiskMasterDuration','EventRefRemarksCounters','EventRefMLID','EventRefMLID2',
      'DubbedLanguage','DubbingArtist','HasSubtitle','SubTitlesLanguage','EditingDeptRemarks','EditingType',
      'BhajanType','IsDubbed','NumberSource','TopicSource','LastModifiedTimestamp','LastModifiedBy',
      'Synopsis','LocationWithinAshram','Keywords','Grading','Segment Category','Segment Duration',
      'TopicgivenBy',
      // Columns from the 'dr' (DigitalRecordings) table
      'PreservationStatus', 'RecordingCode', 'RecordingName', 'fkEventCode'
    ];

    // --- MODIFICATION: Define table aliases for ambiguous columns ---
    const aliases = {
      'IsInformal': 'nml',
      'PreservationStatus': 'dr',
      'RecordingCode': 'dr',
      'RecordingName': 'dr',
      'fkEventCode': 'dr',
      'LastModifiedTimestamp': 'nml'
    };

    // --- MODIFICATION: Call helpers with plain column names and the aliases map ---
    const { whereString: dynamicWhere, params: dynamicParams } = buildWhereClause(req.query, filterableColumns, filterableColumns, aliases);
    const orderByString = buildOrderByClause(req.query, filterableColumns, aliases) || 'ORDER BY nml.MLUniqueID DESC';

    const staticWhere = `
      nml.\`Segment Category\` IN (
        'Product/Webseries',
        'SU - Extracted',
        'Satsang Clips'
      )
      AND (
        dr.PreservationStatus IS NULL
        OR TRIM(dr.PreservationStatus) = ''
        OR UPPER(TRIM(dr.PreservationStatus)) = 'PRESERVE'
      )
    `;

    const finalWhere = dynamicWhere ? `${dynamicWhere} AND (${staticWhere})` : `WHERE ${staticWhere}`;
    const finalParams = [...dynamicParams];

    // --- Count Query ---
    const countQuery = `
      SELECT COUNT(*) as total
      FROM NewMediaLog AS nml
      LEFT JOIN DigitalRecordings AS dr 
        ON nml.fkDigitalRecordingCode = dr.RecordingCode
      ${finalWhere}
    `;
    const [[{ total }]] = await db.query(countQuery, finalParams);
    const totalPages = Math.ceil(total / limit);

    // --- Data Query ---
    const dataQuery = `
      SELECT 
        nml.*,
        dr.PreservationStatus,
        dr.RecordingCode,
        dr.RecordingName,
        dr.fkEventCode
      FROM NewMediaLog AS nml
      LEFT JOIN DigitalRecordings AS dr 
        ON nml.fkDigitalRecordingCode = dr.RecordingCode
      ${finalWhere}
      ${orderByString}
      LIMIT ? OFFSET ?
    `;
    const [rows] = await db.query(dataQuery, [...finalParams, limit, offset]);

    res.json({
      data: rows,
      pagination: {
        page,
        limit,
        totalItems: total,
        totalPages
      }
    });
  } catch (err) {
    console.error("❌ API Error for /api/newmedialog/satsang-extracted-clips:", err);
    res.status(500).json({ error: err.message });
  }
});


// --- Corrected Endpoint for "Satsang Category" (Using your query) ---
// ...existing code...


// --- Corrected Endpoint for "Satsang Category" (Using your query) ---
// ...existing code...
// --- Corrected Endpoint for "Satsang Category" (Using your query) ---
app.get('/api/newmedialog/satsang-category', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;

    const filterableColumns = [
      'MLUniqueID','FootageSrNo', 'LogSerialNo','fkDigitalRecordingCode','ContentFrom','ContentTo',
      'TimeOfDay','fkOccasion','EditingStatus','FootageType','VideoDistribution','Detail','SubDetail',
      'CounterFrom','CounterTo','SubDuration','TotalDuration','Language','SpeakerSinger','fkOrganization',
      'Designation','fkCountry','fkState','fkCity','Venue','fkGranth','Number','Topic','Seriesname',
      'SatsangStart','SatsangEnd','IsAudioRecorded','AudioMP3Distribution','AudioWAVDistribution',
      'AudioMP3DRCode','AudioWAVDRCode','Remarks','IsStartPage','EndPage','IsInformal','IsPPGNotPresent',
      'Guidance','DiskMasterDuration','EventRefRemarksCounters','EventRefMLID','EventRefMLID2',
      'DubbedLanguage','DubbingArtist','HasSubtitle','SubTitlesLanguage','EditingDeptRemarks','EditingType',
      'BhajanType','IsDubbed','NumberSource','TopicSource','LastModifiedTimestamp','LastModifiedBy',
      'Synopsis','LocationWithinAshram','Keywords','Grading','Segment Category','Segment Duration',
      'TopicgivenBy',
      // Columns from the 'dr' (DigitalRecordings) table
      'PreservationStatus', 'RecordingCode', 'RecordingName', 'fkEventCode'
    ];

    // --- MODIFICATION: Define table aliases for ambiguous columns ---
    const aliases = {
      'IsInformal': 'nml',
      'PreservationStatus': 'dr',
      'RecordingCode': 'dr',
      'RecordingName': 'dr',
      'fkEventCode': 'dr',
      'LastModifiedTimestamp': 'nml'
    };

    // --- MODIFICATION: Call helpers with plain column names and the aliases map ---
    const { whereString: dynamicWhere, params: dynamicParams } = buildWhereClause(req.query, filterableColumns, filterableColumns, aliases);
    const orderByString = buildOrderByClause(req.query, filterableColumns, aliases) || 'ORDER BY nml.MLUniqueID DESC';


    const staticWhere = `
      nml.\`Segment Category\` IN (
        'Prasangik Udbodhan', 'SU', 'SU - GM', 'SU - Revision',
        'Satsang', 'Informal Satsang', 'SU - Extracted'
      )
      AND (
        dr.PreservationStatus IS NULL
        OR TRIM(dr.PreservationStatus) = ''
        OR UPPER(TRIM(dr.PreservationStatus)) = 'PRESERVE'
      )
    `;

    const finalWhere = dynamicWhere ? `${dynamicWhere} AND (${staticWhere})` : `WHERE ${staticWhere}`;
    const finalParams = [...dynamicParams];

    // --- Count Query ---
    const countQuery = `
      SELECT COUNT(*) as total
      FROM NewMediaLog AS nml
      LEFT JOIN DigitalRecordings AS dr 
        ON nml.fkDigitalRecordingCode = dr.RecordingCode
      ${finalWhere}
    `;
    const [[{ total }]] = await db.query(countQuery, finalParams);
    const totalPages = Math.ceil(total / limit);

    // --- Data Query ---
    const dataQuery = `
      SELECT 
        nml.*,
        dr.PreservationStatus,
        dr.RecordingCode,
        dr.RecordingName,
        dr.fkEventCode
      FROM NewMediaLog AS nml
      LEFT JOIN DigitalRecordings AS dr 
        ON nml.fkDigitalRecordingCode = dr.RecordingCode
      ${finalWhere}
      ${orderByString}
      LIMIT ? OFFSET ?
    `;
    const [rows] = await db.query(dataQuery, [...finalParams, limit, offset]);

    res.json({
      data: rows,
      pagination: {
        page,
        limit,
        totalItems: total,
        totalPages
      }
    });
  } catch (err) {
    console.error("❌ API Error for /api/newmedialog/satsang-category:", err);
    res.status(500).json({ error: err.message });
  }
});









app.get('/api/newmedialog/export', async (req, res) => {
    try {
        // FIX: Call the generic buildWhereClause function
        const { whereString, params } = buildWhereClause(req.query, ['MLUniqueID', 'Topic', 'SpeakerSinger'], ['MLUniqueID','FootageSrNo', 'LogSerialNo','fkDigitalRecordingCode','ContentFrom','ContentTo', 'TimeOfDay','fkOccasion','EditingStatus','FootageType','VideoDistribution','Details','SubDetails','CounterFrom','CounterTo','SubDuration','TotalDuration','Language','SpeakerSinger','fkOrganization','Designation','fkCountry','fkState','fkCity','Venue','fkGranth','Number','Topic','Seriesname','SatsangStart','SatsangEnd','IsAudioRecorded','AudioMP3Distribution','AudioWAVDistribution','AudioMP3DRCode','AudioWAVDRCode','Remarks','IsStartPage','EndPage','IsInformal','IsPPGNotPresent','Guidance','DiskMasterDuration','EventRefRemarksCounters','EventRefMLID','EventRefMLID2', 'DubbedLanguage','DubbingArtist','HasSubtitle','SubTitlesLanguage','EditingDeptRemarks','EditingType','BhajanType','IsDubbed','NumberSource','TopicSource','LastModifiedTimestamp','LastModifiedBy','Synopsis','LocationWithinAshram','Keywords','Grading' ,'Segment Category','SegmentDuration','TopicgivenBy' /* add more... */]);
        const dataQuery = `SELECT * FROM NewMediaLog ${whereString}`;
        const [results] = await db.query(dataQuery, params);
        if (results.length === 0) {
            return res.status(404).send("No data found to export for the given filters.");
        }
        const headers = Object.keys(results[0]);
        const csvHeader = headers.join(',');
        const csvRows = results.map(row => headers.map(header => {
            const value = row[header];
            const strValue = String(value === null || value === undefined ? '' : value);
            return `"${strValue.replace(/"/g, '""')}"`;
        }).join(','));
        const csvContent = [csvHeader, ...csvRows].join('\n');
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename="newmedialog_export.csv"');
        res.status(200).send(csvContent);
    } catch (err) {
        console.error("Database query error on /api/newmedialog/export:", err);
        res.status(500).json({ error: 'CSV export failed' });
    }
});


app.put('/api/newmedialog/:MLUniqueID', async (req, res) => {
  const { MLUniqueID } = req.params;
  // Destructure all editable fields from the request body
  const {
    FootageSrNo, LogSerialNo, fkDigitalRecordingCode, ContentFrom, ContentTo, TimeOfDay,
    fkOccasion, EditingStatus, FootageType, VideoDistribution, Detail, SubDetail,
    CounterFrom, CounterTo, SubDuration, TotalDuration, Language, SpeakerSinger, fkOrganization,
    Designation, fkCountry, fkState, fkCity, Venue, fkGranth, Number, Topic, SeriesName,
    SatsangStart, SatsangEnd, IsAudioRecorded, AudioMP3Distribution, AudioWAVDistribution,
    AudioMP3DRCode, AudioWAVDRCode, FullWAVDRCode, Remarks, IsStartPage, EndPage, IsInformal,
    IsPPGNotPresent, Guidance, DiskMasterDuration, EventRefRemarksCounters, EventRefMLID,
    EventRefMLID2, DubbedLanguage, DubbingArtist, HasSubtitle, SubTitlesLanguage, EditingDeptRemarks,
    EditingType, BhajanType, IsDubbed, NumberSource, TopicSource, Synopsis, LocationWithinAshram,
    Keywords, Grading, 'Segment Category': SegmentCategory, 'Segment Duration': SegmentDuration,
    TopicGivenBy, LastModifiedBy
  } = req.body;

  if (!MLUniqueID) {
    return res.status(400).json({ error: "MLUniqueID is required." });
  }

  try {
    const query = `
      UPDATE NewMediaLog
      SET
        FootageSrNo = ?,
        LogSerialNo = ?,
        fkDigitalRecordingCode = ?,
        ContentFrom = ?,
        ContentTo = ?,
        TimeOfDay = ?,
        fkOccasion = ?,
        EditingStatus = ?,
        FootageType = ?,
        VideoDistribution = ?,
        Detail = ?,
        SubDetail = ?,
        CounterFrom = ?,
        CounterTo = ?,
        SubDuration = ?,
        TotalDuration = ?,
        Language = ?,
        SpeakerSinger = ?,
        fkOrganization = ?,
        Designation = ?,
        fkCountry = ?,
        fkState = ?,
        fkCity = ?,
        Venue = ?,
        fkGranth = ?,
        Number = ?,
        Topic = ?,
        SeriesName = ?,
        SatsangStart = ?,
        SatsangEnd = ?,
        IsAudioRecorded = ?,
        AudioMP3Distribution = ?,
        AudioWAVDistribution = ?,
        AudioMP3DRCode = ?,
        AudioWAVDRCode = ?,
        FullWAVDRCode = ?,
        Remarks = ?,
        IsStartPage = ?,
        EndPage = ?,
        IsInformal = ?,
        IsPPGNotPresent = ?,
        Guidance = ?,
        DiskMasterDuration = ?,
        EventRefRemarksCounters = ?,
        EventRefMLID = ?,
        EventRefMLID2 = ?,
        DubbedLanguage = ?,
        DubbingArtist = ?,
        HasSubtitle = ?,
        SubTitlesLanguage = ?,
        EditingDeptRemarks = ?,
        EditingType = ?,
        BhajanType = ?,
        IsDubbed = ?,
        NumberSource = ?,
        TopicSource = ?,
        Synopsis = ?,
        LocationWithinAshram = ?,
        Keywords = ?,
        Grading = ?,
        \`Segment Category\` = ?,
        \`Segment Duration\` = ?,
        TopicGivenBy = ?,
        LastModifiedBy = ?,
        LastModifiedTimestamp = NOW()
      WHERE MLUniqueID = ?
    `;

    const [result] = await db.query(query, [
      FootageSrNo, LogSerialNo, fkDigitalRecordingCode, ContentFrom, ContentTo, TimeOfDay,
      fkOccasion, EditingStatus, FootageType, VideoDistribution, Detail, SubDetail,
      CounterFrom, CounterTo, SubDuration, TotalDuration, Language, SpeakerSinger, fkOrganization,
      Designation, fkCountry, fkState, fkCity, Venue, fkGranth, Number, Topic, SeriesName,
      SatsangStart, SatsangEnd, IsAudioRecorded, AudioMP3Distribution, AudioWAVDistribution,
      AudioMP3DRCode, AudioWAVDRCode, FullWAVDRCode, Remarks, IsStartPage, EndPage, IsInformal,
      IsPPGNotPresent, Guidance, DiskMasterDuration, EventRefRemarksCounters, EventRefMLID,
      EventRefMLID2, DubbedLanguage, DubbingArtist, HasSubtitle, SubTitlesLanguage, EditingDeptRemarks,
      EditingType, BhajanType, IsDubbed, NumberSource, TopicSource, Synopsis, LocationWithinAshram,
      Keywords, Grading, SegmentCategory, SegmentDuration, TopicGivenBy, LastModifiedBy || '', MLUniqueID
    ]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: `Media Log with ID ${MLUniqueID} not found.` });
    }

    res.status(200).json({ message: "Media Log updated successfully." });
  } catch (err) {
    console.error("❌ Database query error on /api/newmedialog/:MLUniqueID:", err);
    res.status(500).json({ error: "Failed to update Media Log." });
  }
});

// --- UPGRADED DigitalRecording Endpoints ---
app.get('/api/digitalrecording', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;

    const filterableColumns = [
      'fkEventCode',
      'RecordingName',
      'RecordingCode',
      'NoOfFiles',
      'FilesizeInBytes',
        'fkDigitalMasterCategory',
        'fkMediaName',
        'BitRate',
        'AudioBitrate',
        'Filesize',
        'Duration',
        'AudioTotalDuration',
        'RecordingRemarks',
        'CounterError',
        'ReasonError',
        'QcRemarksCheckedOn',
        'PreservationStatus',
        'QcSevak',
        'MasterProductTitle',
        'Qcstatus',
        'LastModifiedTimestamp',
        'fkDistributionLabel',
        'SubmittedDate',
        'PresStatGuidDt',
        'InfoOnCassette',
        'Masterquality',
        'IsInformal',
        'AssociatedDR',
        'Dimension',
        'ProductionBucket',
        'DistributionDriveLink',
        'Teams'

    ];

    const { whereString, params } = buildWhereClause(
      req.query,
      [ 'fkEventCode',
      'RecordingName',
      'RecordingCode',
      'NoOfFiles',
      'FilesizeInBytes',
        'fkDigitalMasterCategory',
        'fkMediaName',
        'BitRate',
        'AudioBitrate',
        'Filesize',
        'Duration',
        'AudioTotalDuration',
        'RecordingRemarks',
        'CounterError',
        'ReasonError',
        'QcRemarksCheckedOn',
        'PreservationStatus',
        'QcSevak',
        'MasterProductTitle',
        'Qcstatus',
        'LastModifiedTimestamp',
        'fkDistributionLabel',
        'SubmittedDate',
        'PresStatGuidDt',
        'InfoOnCassette',
        'Masterquality',
        'IsInformal',
        'AssociatedDR',
        'Dimension',
        'ProductionBucket',
        'DistributionDriveLink',
        'Teams'], // global search fields
      filterableColumns
    );

    const orderByString = buildOrderByClause(req.query, filterableColumns);

    // --- Count Query ---
    const countQuery = `SELECT COUNT(*) as total FROM DigitalRecordings ${whereString}`;
    const [[{ total }]] = await db.query(countQuery, params);
    const totalPages = Math.ceil(total / limit);

    // --- Data Query ---
    const dataQuery = `
      SELECT * 
      FROM DigitalRecordings 
      ${whereString} 
      ${orderByString}
      LIMIT ? OFFSET ?
    `;
    const [results] = await db.query(dataQuery, [...params, limit, offset]);

    res.json({
      data: results,
      pagination: {
        page,
        limit,
        totalItems: total,
        totalPages
      }
    });
  } catch (err) {
    console.error("❌ Database query error on /api/digitalrecording:", err);
    res.status(500).json({ error: 'Database query failed' });
  }
});


app.get('/api/digitalrecording/export', async (req, res) => {
    try {
        const { whereString, params } = buildWhereClause(req.query, ['fkEventCode', 'RecordingName'], ['fkEventCode', 'RecordingName', 'RecordingCode', 'NoOfFiles','fkDigitalMasterCategory','fkMediaName','BitRate','AudioBitrate','Filesize','Duration','AudioTotalDuration','RecordingRemarks','CounterError','ReasonError','QcRemarksCheckedOn','PreservationStatus','QcSevak','MasterProductTitle','Qcstatus','LastModifiedTimestamp','fkDistributionLabel','SubmittedDate','PresStatGuidDt','InfoOnCassette','Masterquality','IsInformal', 'FilesizeInBytes','AssociatedDR','Dimension','ProductionBucket','DistributionDriveLink','Teams']);
        const dataQuery = `SELECT * FROM DigitalRecordings ${whereString}`;
        const [results] = await db.query(dataQuery, params);
        if (results.length === 0) {
            return res.status(404).send("No data found to export for the given filters.");
        }
        const headers = Object.keys(results[0]);
        const csvHeader = headers.join(',');
        const csvRows = results.map(row => headers.map(header => {
            const value = row[header];
            const strValue = String(value === null || value === undefined ? '' : value);
            return `"${strValue.replace(/"/g, '""')}"`;
        }).join(','));
        const csvContent = [csvHeader, ...csvRows].join('\n');
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename="digitalrecordings_export.csv"');
        res.status(200).send(csvContent);
    } catch (err) {
        console.error("Database query error on /api/digitalrecording/export:", err);
        res.status(500).json({ error: 'CSV export failed' });
    }
});


app.put('/api/digitalrecording/:RecordingCode', async (req, res) => {
  const { RecordingCode } = req.params;
  const {
    fkEventCode, RecordingName, NoOfFiles, fkDigitalMasterCategory, fkMediaName,
    BitRate, AudioBitrate, Filesize, Duration, AudioTotalDuration, RecordingRemarks,
    CounterError, ReasonError, QcRemarksCheckedOn, PreservationStatus, QCSevak,
    MasterProductTitle, QcStatus, fkDistributionLabel, SubmittedDate, PresStatGuidDt,
    InfoOnCassette, Masterquality, IsInformal, FilesizeInBytes, AssociatedDR, Dimension,
    ProductionBucket, DistributionDriveLink, Teams, LastModifiedBy
  } = req.body;

  if (!RecordingCode) {
    return res.status(400).json({ error: "RecordingCode is required." });
  }

  try {
    const query = `
      UPDATE DigitalRecordings
      SET
        fkEventCode = ?,
        RecordingName = ?,
        NoOfFiles = ?,
        fkDigitalMasterCategory = ?,
        fkMediaName = ?,
        BitRate = ?,
        AudioBitrate = ?,
        Filesize = ?,
        Duration = ?,
        AudioTotalDuration = ?,
        RecordingRemarks = ?,
        CounterError = ?,
        ReasonError = ?,
        QcRemarksCheckedOn = ?,
        PreservationStatus = ?,
        QCSevak = ?,
        MasterProductTitle = ?,
        QcStatus = ?,
        fkDistributionLabel = ?,
        SubmittedDate = ?,
        PresStatGuidDt = ?,
        InfoOnCassette = ?,
        Masterquality = ?,
        IsInformal = ?,
        FilesizeInBytes = ?,
        AssociatedDR = ?,
        Dimension = ?,
        ProductionBucket = ?,
        DistributionDriveLink = ?,
        Teams = ?,
        LastModifiedBy = ?,
        LastModifiedTimestamp = NOW()
      WHERE RecordingCode = ?
    `;

    const [result] = await db.query(query, [
      fkEventCode, RecordingName, NoOfFiles, fkDigitalMasterCategory, fkMediaName,
      BitRate, AudioBitrate, Filesize, Duration, AudioTotalDuration, RecordingRemarks,
      CounterError, ReasonError, QcRemarksCheckedOn, PreservationStatus, QCSevak,
      MasterProductTitle, QcStatus, fkDistributionLabel, SubmittedDate, PresStatGuidDt,
      InfoOnCassette, Masterquality, IsInformal, FilesizeInBytes, AssociatedDR, Dimension,
      ProductionBucket, DistributionDriveLink, Teams, LastModifiedBy || '', RecordingCode
    ]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: `Digital Recording with code ${RecordingCode} not found.` });
    }

    res.status(200).json({ message: "Digital Recording updated successfully." });
  } catch (err) {
    console.error("❌ Database query error on /api/digitalrecording/:RecordingCode:", err);
    res.status(500).json({ error: "Failed to update Digital Recording." });
  }
});
// --- NEW ENDPOINTS FOR AUXFILES TABLE ---

// Endpoint to get all records from the AuxFiles table
app.get('/api/auxfiles', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;

    const filterableColumns = [
      'AUXID',
      'new_auxid',
      'AuxCode',
      'fkMLID',
      'NoOfFiles',
      'FilesizeBytes',
      'ProjFileSize',
      'AuxTopic',
      'NotesRemarks',
      'AuxLanguage',
        'AuxFileType',
        'GoogleDriveLink',
        'LastModifiedTimestamp',
        'LastModifiedBy',
        'ProjFileCode',
        'ProjFileName',
        'SRTLink',
        'CreatedOn',
        'CreatedBy',
        'ModifiedOn',
        'ModifiedBy'

      // ✅ Add more filterable columns here as needed
    ];

    const { whereString, params } = buildWhereClause(
      req.query,
      [ 'AUXID',
      'new_auxid',
      'AuxCode',
      'fkMLID',
      'NoOfFiles',
      'FilesizeBytes',
      'ProjFileSize',
      'AuxTopic',
      'NotesRemarks',
      'AuxLanguage',
        'AuxFileType',
        'GoogleDriveLink',
        'LastModifiedTimestamp',
        'LastModifiedBy',
        'ProjFileCode',
        'ProjFileName',
        'SRTLink',
        'CreatedOn',
        'CreatedBy',
        'ModifiedOn',
        'ModifiedBy'], // global search fields
      filterableColumns
    );

    const orderByString = buildOrderByClause(req.query, filterableColumns);

    // --- Count Query ---
    const countQuery = `SELECT COUNT(*) as total FROM AuxFiles ${whereString}`;
    const [[{ total }]] = await db.query(countQuery, params);
    const totalPages = Math.ceil(total / limit);

    // --- Data Query ---
    const dataQuery = `
      SELECT * 
      FROM AuxFiles 
      ${whereString} 
      ${orderByString}
      LIMIT ? OFFSET ?
    `;
    const [results] = await db.query(dataQuery, [...params, limit, offset]);

    res.json({
      data: results,
      pagination: {
        page,
        limit,
        totalItems: total,
        totalPages
      }
    });
  } catch (err) {
    console.error("❌ Database query error on /api/auxfiles:", err);
    res.status(500).json({ error: 'Database query failed' });
  }
});


app.get('/api/auxfiles/export', async (req, res) => {
    try {
        const { whereString, params } = buildWhereClause(req.query, ['AuxCode', 'AuxTopic', 'NotesRemarks'], ['AUXID', 'new_auxid', 'AuxCode', 'AuxFileType','AuxLanguage','fkMLID','AuxTopic','NotesRemarks','GoogleDriveLink', 'NoOfFiles', 'FilesizeBytes', 'LastModifiedTimestamp','LastModifiedBy','ProjFileCode','ProjFileSize' , 'ProjFileName','SRTLink','CreatedOn','CreatedBy' ,'ModifiedOn','ModifiedBy' ]);
        const dataQuery = `SELECT * FROM AuxFiles ${whereString}`;
        const [results] = await db.query(dataQuery, params);
        if (results.length === 0) {
            return res.status(404).send("No data found to export for the given filters.");
        }
        const headers = Object.keys(results[0]);
        const csvHeader = headers.join(',');
        const csvRows = results.map(row => headers.map(header => {
            const value = row[header];
            const strValue = String(value === null || value === undefined ? '' : value);
            return `"${strValue.replace(/"/g, '""')}"`;
        }).join(','));
        const csvContent = [csvHeader, ...csvRows].join('\n');
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename="auxfiles_export.csv"');
        res.status(200).send(csvContent);
    } catch (err) {
        console.error("Database query error on /api/auxfiles/export:", err);
        res.status(500).json({ error: 'CSV export failed' });
    }
});

// Endpoint to get a single auxiliary file by its code
app.get('/api/auxfiles/:fkMLID', async (req, res) => {
    const { fkMLID } = req.params;
    try {
        const [results] = await db.query('SELECT * FROM AuxFiles WHERE fkMLID = ?', [fkMLID]);

        if (results.length === 0) {
            return res.status(404).json({ message: `Auxiliary file with code ${fkMLID} not found.` });
        }
        res.json(results[0]);
    } catch (err) {
        console.error("Database query error on single auxiliary file:", err);
        return res.status(500).json({ error: 'Database query failed' });
    }
});


app.put('/api/aux/:new_auxid', async (req, res) => {
  const { new_auxid } = req.params; // Extract the `new_auxid` from the URL
  const { SRTLink } = req.body; // Extract the `SRTLink` from the request body

  if (!new_auxid) {
    return res.status(400).json({ error: "Auxiliary file ID (new_auxid) is required." });
  }

  if (!SRTLink) {
    return res.status(400).json({ error: "SRTLink is required." });
  }

  try {
    const query = `
      UPDATE AuxFiles
      SET SRTLink = ?, ModifiedOn = NOW()
      WHERE new_auxid = ?
    `;

    const [result] = await db.query(query, [SRTLink, new_auxid]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: `Auxiliary file with ID ${new_auxid} not found.` });
    }

    res.status(200).json({ message: "SRT Link updated successfully." });
  } catch (err) {
    console.error("❌ Database query error on /api/aux/:new_auxid:", err);
    res.status(500).json({ error: "Failed to update SRT Link." });
  }
});

app.put('/api/auxfiles/:new_auxid', async (req, res) => {
  const { new_auxid } = req.params;
  const {
    AuxCode, AuxFileType, AuxLanguage, fkMLID, AuxTopic, NotesRemarks, GoogleDriveLink,
    NoOfFiles, FilesizeBytes, ProjFileCode, ProjFileSize, ProjFileName, SRTLink,
    CreatedOn, CreatedBy, ModifiedOn, ModifiedBy, LastModifiedBy
  } = req.body;

  if (!new_auxid) {
    return res.status(400).json({ error: "new_auxid is required." });
  }

  try {
    const query = `
      UPDATE AuxFiles
      SET
        AuxCode = ?,
        AuxFileType = ?,
        AuxLanguage = ?,
        fkMLID = ?,
        AuxTopic = ?,
        NotesRemarks = ?,
        GoogleDriveLink = ?,
        NoOfFiles = ?,
        FilesizeBytes = ?,
        ProjFileCode = ?,
        ProjFileSize = ?,
        ProjFileName = ?,
        SRTLink = ?,
        CreatedOn = ?,
        CreatedBy = ?,
        ModifiedOn = ?,
        ModifiedBy = ?,
        LastModifiedBy = ?,
        LastModifiedTimestamp = NOW()
      WHERE new_auxid = ?
    `;

    const [result] = await db.query(query, [
      AuxCode, AuxFileType, AuxLanguage, fkMLID, AuxTopic, NotesRemarks, GoogleDriveLink,
      NoOfFiles, FilesizeBytes, ProjFileCode, ProjFileSize, ProjFileName, SRTLink,
      CreatedOn, CreatedBy, ModifiedOn, ModifiedBy, LastModifiedBy || '', new_auxid
    ]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: `Aux file with new_auxid ${new_auxid} not found.` });
    }

    res.status(200).json({ message: "Aux file updated successfully." });
  } catch (err) {
    console.error("❌ Database query error on /api/auxfiles/:new_auxid:", err);
    res.status(500).json({ error: "Failed to update Aux file." });
  }
}); 
// --- ENDPOINTS FOR SINGLE RECORDS ---

// Endpoint to get a single event by EventCode
// --- Get a single Event by EventCode ---
app.get('/api/events/:eventCode', async (req, res) => {
  const { eventCode } = req.params;
  try {
    const [results] = await db.query(
      'SELECT * FROM Events WHERE EventCode = ?',
      [eventCode]
    );

    if (!results || results.length === 0) {
      return res.status(404).json({ message: `Event with code ${eventCode} not found.` });
    }

    res.json(results[0]);
  } catch (err) {
    console.error("Database query error on single event:", err);
    res.status(500).json({ error: 'Database query failed' });
  }
});


// --- Get a single Digital Recording by RecordingCode ---
app.get('/api/digitalrecordings/:recordingCode', async (req, res) => {
  const { recordingCode } = req.params;
  try {
    const [results] = await db.query(
      'SELECT * FROM DigitalRecordings WHERE RecordingCode = ?',
      [recordingCode]
    );

    if (!results || results.length === 0) {
      return res.status(404).json({ message: `Digital Recording with code ${recordingCode} not found.` });
    }

    res.json(results[0]);
  } catch (err) {
    console.error("Database query error on single digital recording:", err);
    res.status(500).json({ error: 'Database query failed' });
  }
});

// Place this BEFORE any app.get('/api/newmedialog/:id') routes
app.get('/api/newmedialog/pratishtha', async (req, res) => {
  try {
    // Calculate the date 90 days ago
    const ninetyDaysAgo = new Date();
    ninetyDaysAgo.setDate(ninetyDaysAgo.getDate() - 90);
    const formattedDate = ninetyDaysAgo.toISOString().slice(0, 19).replace("T", " "); // MySQL DATETIME

    const query = `
      SELECT MLUniqueID, \`Segment Category\`
      FROM NewMediaLog
      WHERE \`Segment Category\` = 'Pratishtha'
        AND ContentTo >= ?
      ORDER BY ContentTo DESC
    `;

    const countQuery = `
      SELECT COUNT(*) AS count
      FROM NewMediaLog
      WHERE \`Segment Category\` = 'Pratishtha'
        AND ContentTo >= ?
    `;

    const [results] = await db.query(query, [formattedDate]);
    const [[{ count }]] = await db.query(countQuery, [formattedDate]);

    res.status(200).json({ count, data: results });
  } catch (err) {
    console.error("❌ Database query error on /api/newmedialog/pratishtha:", err);
    res.status(500).json({ error: 'Failed to fetch Pratishtha data.' });
  }
});



app.get('/api/newmedialog/padhramani', async (req, res) => {
  try {
    // Calculate the date 90 days ago
    const ninetyDaysAgo = new Date();
    ninetyDaysAgo.setDate(ninetyDaysAgo.getDate() - 90);
    const formattedDate = ninetyDaysAgo.toISOString().slice(0, 19).replace("T", " "); // MySQL DATETIME

    const query = `
      SELECT MLUniqueID, \`Segment Category\`
      FROM NewMediaLog
      WHERE \`Segment Category\` = 'Padhramani'
        AND ContentTo >= ?
      ORDER BY ContentTo DESC
    `;

    const countQuery = `
      SELECT COUNT(*) AS count
      FROM NewMediaLog
      WHERE \`Segment Category\` = 'Padhramani'
        AND ContentTo >= ?
    `;

    const [results] = await db.query(query, [formattedDate]);
    const [[{ count }]] = await db.query(countQuery, [formattedDate]);

    res.status(200).json({ count, data: results });
  } catch (err) {
    console.error("❌ Database query error on /api/newmedialog/padhramani:", err);
    res.status(500).json({ error: 'Failed to fetch Padhramani data.' });
  }
});

// --- NEW ENDPOINT: Fetch distinct cities from the last 90 days ---
app.get('/api/newmedialog/city', async (req, res) => {
  try {
    // Calculate the date 90 days ago
    const ninetyDaysAgo = new Date();
    ninetyDaysAgo.setDate(ninetyDaysAgo.getDate() - 90);
    const formattedDate = ninetyDaysAgo.toISOString().slice(0, 19).replace("T", " "); // MySQL DATETIME format

    const query = `
      SELECT DISTINCT fkCity
      FROM NewMediaLog
      WHERE fkCity IS NOT NULL AND fkCity <> ''
        AND ContentTo >= ?
      ORDER BY fkCity ASC
    `;

    const countQuery = `
      SELECT COUNT(DISTINCT fkCity) AS count
      FROM NewMediaLog
      WHERE fkCity IS NOT NULL AND fkCity <> ''
        AND ContentTo >= ?
    `;

    const [results] = await db.query(query, [formattedDate]);
    const [[{ count }]] = await db.query(countQuery, [formattedDate]);

    res.status(200).json({ count, data: results });
  } catch (err) {
    console.error("❌ Database query error on /api/newmedialog/city:", err);
    res.status(500).json({ error: 'Failed to fetch City data.' });
  }
});

// --- NEW ENDPOINT: Fetch distinct countries from the last 90 days ---
app.get('/api/newmedialog/country', async (req, res) => {
  try {
    // Calculate the date 90 days ago
    const ninetyDaysAgo = new Date();
    ninetyDaysAgo.setDate(ninetyDaysAgo.getDate() - 90);
    const formattedDate = ninetyDaysAgo.toISOString().slice(0, 19).replace("T", " "); // MySQL DATETIME format

    const query = `
      SELECT DISTINCT fkCountry
      FROM NewMediaLog
      WHERE fkCountry IS NOT NULL AND fkCountry <> ''
        AND ContentTo >= ?
      ORDER BY fkCountry ASC
    `;

    const countQuery = `
      SELECT COUNT(DISTINCT fkCountry) AS count
      FROM NewMediaLog
      WHERE fkCountry IS NOT NULL AND fkCountry <> ''
        AND ContentTo >= ?
    `;

    const [results] = await db.query(query, [formattedDate]);
    const [[{ count }]] = await db.query(countQuery, [formattedDate]);

    res.status(200).json({ count, data: results });
  } catch (err) {
    console.error("❌ Database query error on /api/newmedialog/country:", err);
    res.status(500).json({ error: 'Failed to fetch Country data.' });
  }
});

// --- Get a single New Media Log by MLUniqueID ---
app.get('/api/newmedialog/:mlid', async (req, res) => {
  const { mlid } = req.params;
  try {
    const [results] = await db.query(
      'SELECT * FROM NewMediaLog WHERE MLUniqueID = ?',
      [mlid]
    );

    if (!results || results.length === 0) {
      return res.status(404).json({ message: `Media Log with ID ${mlid} not found.` });
    }

    res.json(results[0]);
  } catch (err) {
    console.error("Database query error on single media log:", err);
    res.status(500).json({ error: 'Database query failed' });
  }
});


app.get('/api/dashboard/countries-visited', async (req, res) => {
    const { year } = req.query;

    if (!year) {
        return res.status(400).json({ error: 'Year query parameter is required.' });
    }

    try {
        const query = `
            SELECT
    nml.fkCountry AS name,
    COUNT(*) AS visits
FROM Events AS e
INNER JOIN DigitalRecordings AS dr 
    ON e.EventCode = dr.fkEventCode
INNER JOIN NewMediaLog AS nml 
    ON dr.RecordingCode = nml.fkDigitalRecordingCode
WHERE
    e.Yr = ?
    AND nml.fkCountry IS NOT NULL
    AND nml.fkCountry <> ''
GROUP BY
    nml.fkCountry
ORDER BY
    visits DESC -- Limit to a reasonable number for a chart
        `;

        const [results] = await db.query(query, [year]);
        res.json(results);

    } catch (err) {
        console.error("Database query error on /api/dashboard/countries-visited:", err);
        res.status(500).json({ error: 'Failed to fetch dashboard data' });
    }
});


// --- NEW ENDPOINT FOR EVENT DETAILS BY COUNTRY AND YEAR ---
app.get('/api/dashboard/events-by-country', async (req, res) => {
    const { year, country } = req.query;

    if (!year || !country) {
        return res.status(400).json({ error: 'Year and Country query parameters are required.' });
    }

    try {
        const query = `
             SELECT
                e.EventCode,
                e.EventName,
                nml.Detail,
                dr.RecordingCode,
                nml.fkCountry,
                nml.fkCity,              -- ✅ Added city info
                nml.*,
                COUNT(*) OVER (PARTITION BY nml.fkCountry) AS visits_for_country
            FROM Events AS e
            INNER JOIN DigitalRecordings AS dr 
                ON e.EventCode = dr.fkEventCode
            INNER JOIN NewMediaLog AS nml 
                ON dr.RecordingCode = nml.fkDigitalRecordingCode
            WHERE
                e.Yr = ?
                AND nml.fkCountry IS NOT NULL
                AND nml.fkCountry <> ''
                AND nml.fkCountry = ?
            ORDER BY
                visits_for_country DESC, 
                nml.fkCity; -- ✅ Optional: order by city inside the country
        `;

        const [results] = await db.query(query, [year, country]);
        res.json(results);

    } catch (err) {
        console.error("Database query error on /api/dashboard/events-by-country:", err);
        res.status(500).json({ error: 'Failed to fetch event details' });
    }
});

// --- NEW ENDPOINT FOR CITIES VISITED ---
app.get('/api/dashboard/cities-visited', async (req, res) => {
    const { year } = req.query;

    if (!year) {
        return res.status(400).json({ error: 'Year query parameter is required.' });
    }

    try {
        const query = `
            SELECT
                nml.fkCity AS name,
                COUNT(*) AS visits
            FROM Events AS e
            INNER JOIN DigitalRecordings AS dr 
                ON e.EventCode = dr.fkEventCode
            INNER JOIN NewMediaLog AS nml 
                ON dr.RecordingCode = nml.fkDigitalRecordingCode
            WHERE
                e.Yr = ?
                AND nml.fkCity IS NOT NULL
                AND nml.fkCity <> ''
            GROUP BY 
                nml.fkCity
            ORDER BY 
                visits DESC
             -- Get the top 10 cities
        `;

        const [results] = await db.query(query, [year]);
        res.json(results);

    } catch (err) {
        console.error("Database query error on /api/dashboard/cities-visited:", err);
        res.status(500).json({ error: 'Failed to fetch city data' });
    }
});

// --- ADD THIS NEW ENDPOINT for fetching details by city ---
app.get('/api/dashboard/events-by-city', async (req, res) => {
    const { year, city } = req.query;

    if (!year || !city) {
        return res.status(400).json({ error: 'Year and City query parameters are required.' });
    }

    try {
        const query = `
              SELECT
                e.EventCode,
                e.EventName,
                e.FromDate,
                e.ToDate,
                nml.MLUniqueID,
                nml.Detail AS Detail, -- Aliased for consistency
                nml.fkCity,
                nml.fkCountry
            FROM Events AS e
            INNER JOIN DigitalRecordings AS dr ON e.EventCode = dr.fkEventCode
            INNER JOIN NewMediaLog AS nml ON dr.RecordingCode = nml.fkDigitalRecordingCode
            WHERE e.Yr = ? AND nml.fkCity = ?
            ORDER BY e.FromDate, nml.LogSerialNo;
        `;

        const [results] = await db.query(query, [year, city]);
        res.json(results);

    } catch (err) {
        console.error("Database query error on /api/dashboard/events-by-city:", err);
        res.status(500).json({ error: 'Failed to fetch event details for city' });
    }
});


// In a real application, this might come from a dedicated 'countries' table in your DB.
// ✅ Define this BEFORE any routes
const countryCoordinates = {
  'Afghanistan': { lat: 33.9391, lng: 67.7100 },
  'Albania': { lat: 41.1533, lng: 20.1683 },
  'Algeria': { lat: 28.0339, lng: 1.6596 },
  'Andorra': { lat: 42.5063, lng: 1.5218 },
  'Angola': { lat: -11.2027, lng: 17.8739 },
  'Antigua and Barbuda': { lat: 17.0608, lng: -61.7964 },
  'Argentina': { lat: -38.4161, lng: -63.6167 },
  'Armenia': { lat: 40.0691, lng: 45.0382 },
  'Australia': { lat: -25.2744, lng: 133.7751 },
  'Austria': { lat: 47.5162, lng: 14.5501 },
  'Azerbaijan': { lat: 40.1431, lng: 47.5769 },
  'Bahamas': { lat: 25.0343, lng: -77.3963 },
  'Bahrain': { lat: 26.0667, lng: 50.5577 },
  'Bangladesh': { lat: 23.6850, lng: 90.3563 },
  'Barbados': { lat: 13.1939, lng: -59.5432 },
  'Belarus': { lat: 53.7098, lng: 27.9534 },
  'Belgium': { lat: 50.8503, lng: 4.3517 },
  'Belize': { lat: 17.1899, lng: -88.4976 },
  'Benin': { lat: 9.3077, lng: 2.3158 },
  'Bhutan': { lat: 27.5142, lng: 90.4336 },
  'Bolivia': { lat: -16.2902, lng: -63.5887 },
  'Bosnia and Herzegovina': { lat: 43.9159, lng: 17.6791 },
  'Botswana': { lat: -22.3285, lng: 24.6849 },
  'Brazil': { lat: -14.2350, lng: -51.9253 },
  'Brunei': { lat: 4.5353, lng: 114.7277 },
  'Bulgaria': { lat: 42.7339, lng: 25.4858 },
  'Burkina Faso': { lat: 12.2383, lng: -1.5616 },
  'Burundi': { lat: -3.3731, lng: 29.9189 },
  'Cambodia': { lat: 12.5657, lng: 104.9910 },
  'Cameroon': { lat: 7.3697, lng: 12.3547 },
  'Canada': { lat: 56.1304, lng: -106.3468 },
  'Chile': { lat: -35.6751, lng: -71.5430 },
  'China': { lat: 35.8617, lng: 104.1954 },
  'Colombia': { lat: 4.5709, lng: -74.2973 },
  'Costa Rica': { lat: 9.7489, lng: -83.7534 },
  'Croatia': { lat: 45.1000, lng: 15.2000 },
  'Cuba': { lat: 21.5218, lng: -77.7812 },
  'Cyprus': { lat: 35.1264, lng: 33.4299 },
  'Czech Republic': { lat: 49.8175, lng: 15.4730 },
  'Denmark': { lat: 56.2639, lng: 9.5018 },
  'Dominican Republic': { lat: 18.7357, lng: -70.1627 },
  'Ecuador': { lat: -1.8312, lng: -78.1834 },
  'Egypt': { lat: 26.8206, lng: 30.8025 },
  'El Salvador': { lat: 13.7942, lng: -88.8965 },
  'Estonia': { lat: 58.5953, lng: 25.0136 },
  'Ethiopia': { lat: 9.1450, lng: 40.4897 },
  'Finland': { lat: 61.9241, lng: 25.7482 },
  'France': { lat: 46.6034, lng: 1.8883 },
  'Germany': { lat: 51.1657, lng: 10.4515 },
  'Greece': { lat: 39.0742, lng: 21.8243 },
  'Hungary': { lat: 47.1625, lng: 19.5033 },
  'Iceland': { lat: 64.9631, lng: -19.0208 },
  'India': { lat: 20.5937, lng: 78.9629 },
  'Indonesia': { lat: -0.7893, lng: 113.9213 },
  'Iran': { lat: 32.4279, lng: 53.6880 },
  'Iraq': { lat: 33.2232, lng: 43.6793 },
  'Ireland': { lat: 53.3331, lng: -8.0 },
  'Israel': { lat: 31.0461, lng: 34.8516 },
  'Italy': { lat: 41.8719, lng: 12.5674 },
  'Japan': { lat: 36.2048, lng: 138.2529 },
  'Kenya': { lat: -0.0236, lng: 37.9062 },
  'Kuwait': { lat: 29.3117, lng: 47.4818 },
  'Latvia': { lat: 56.8796, lng: 24.6032 },
  'Lebanon': { lat: 33.8547, lng: 35.8623 },
  'Lithuania': { lat: 55.1694, lng: 23.8813 },
  'Luxembourg': { lat: 49.8153, lng: 6.1296 },
  'Malaysia': { lat: 4.2105, lng: 101.9758 },
  'Mexico': { lat: 23.6345, lng: -102.5528 },
  'Morocco': { lat: 31.7917, lng: -7.0926 },
  'Nepal': { lat: 28.3949, lng: 84.1240 },
  'Netherlands': { lat: 52.1326, lng: 5.2913 },
  'New Zealand': { lat: -40.9006, lng: 174.8860 },
  'Nigeria': { lat: 9.0820, lng: 8.6753 },
  'Norway': { lat: 60.4720, lng: 8.4689 },
  'Oman': { lat: 21.4735, lng: 55.9754 },
  'Pakistan': { lat: 30.3753, lng: 69.3451 },
  'Panama': { lat: 8.5380, lng: -80.7821 },
  'Paraguay': { lat: -23.4425, lng: -58.4438 },
  'Peru': { lat: -9.1900, lng: -75.0152 },
  'Philippines': { lat: 12.8797, lng: 121.7740 },
  'Poland': { lat: 51.9194, lng: 19.1451 },
  'Portugal': { lat: 39.3999, lng: -8.2245 },
  'Qatar': { lat: 25.276987, lng: 51.520008 },
  'Romania': { lat: 45.9432, lng: 24.9668 },
  'Russia': { lat: 61.5240, lng: 105.3188 },
  'Saudi Arabia': { lat: 23.8859, lng: 45.0792 },
  'Singapore': { lat: 1.3521, lng: 103.8198 },
  'Slovakia': { lat: 48.6690, lng: 19.6990 },
  'Slovenia': { lat: 46.1512, lng: 14.9955 },
  'South Africa': { lat: -30.5595, lng: 22.9375 },
  'South Korea': { lat: 35.9078, lng: 127.7669 },
  'Spain': { lat: 40.4637, lng: -3.7492 },
  'Sri Lanka': { lat: 7.8731, lng: 80.7718 },
  'Sweden': { lat: 60.1282, lng: 18.6435 },
  'Switzerland': { lat: 46.8182, lng: 8.2275 },
  'Thailand': { lat: 15.8700, lng: 100.9925 },
  'Turkey': { lat: 38.9637, lng: 35.2433 },
  'UAE': { lat: 23.4241, lng: 53.8478 },
  'UK': { lat: 55.3781, lng: -3.4360 },
  'USA': { lat: 37.0902, lng: -95.7129 },
  'Ukraine': { lat: 48.3794, lng: 31.1656 },
  'Uruguay': { lat: -32.5228, lng: -55.7658 },
  'Uzbekistan': { lat: 41.3775, lng: 64.5853 },
  'Venezuela': { lat: 6.4238, lng: -66.5897 },
  'Vietnam': { lat: 14.0583, lng: 108.2772 },
  'Yemen': { lat: 15.5527, lng: 48.5164 },
  'Zambia': { lat: -13.1339, lng: 27.8493 },
  'Zimbabwe': { lat: -19.0154, lng: 29.1549 }
};

// Optional normalization mapping
const countryNameMapping = {
  'Afghanistan': 'Afghanistan',
  'Albania': 'Albania',
  'Algeria': 'Algeria',
  'Andorra': 'Andorra',
  'Angola': 'Angola',
  'Argentina': 'Argentina',
  'Armenia': 'Armenia',
  'Australia': 'Australia',
  'Austria': 'Austria',
  'Azerbaijan': 'Azerbaijan',
  'Bahamas': 'Bahamas',
  'Bahrain': 'Bahrain',
  'Bangladesh': 'Bangladesh',
  'Barbados': 'Barbados',
  'Belarus': 'Belarus',
  'Belgium': 'Belgium',
  'Belize': 'Belize',
  'Benin': 'Benin',
  'Bhutan': 'Bhutan',
  'Bolivia': 'Bolivia',
  'Bosnia and Herzegovina': 'Bosnia and Herzegovina',
  'Botswana': 'Botswana',
  'Brazil': 'Brazil',
  'Brunei': 'Brunei',
  'Bulgaria': 'Bulgaria',
  'Burkina Faso': 'Burkina Faso',
  'Burundi': 'Burundi',
  'Cambodia': 'Cambodia',
  'Cameroon': 'Cameroon',
  'Canada': 'Canada',
  'Chile': 'Chile',
  'China': 'China',
  'Colombia': 'Colombia',
  'Costa Rica': 'Costa Rica',
  'Croatia': 'Croatia',
  'Cuba': 'Cuba',
  'Cyprus': 'Cyprus',
  'Czech Republic': 'Czech Republic',
  'Denmark': 'Denmark',
  'Dominican Republic': 'Dominican Republic',
  'Ecuador': 'Ecuador',
  'Egypt': 'Egypt',
  'El Salvador': 'El Salvador',
  'Estonia': 'Estonia',
  'Ethiopia': 'Ethiopia',
  'Finland': 'Finland',
  'France': 'France',
  'Germany': 'Germany',
  'Greece': 'Greece',
  'Hungary': 'Hungary',
  'Iceland': 'Iceland',
  'India': 'India',
  'Indonesia': 'Indonesia',
  'Iran': 'Iran',
  'Iraq': 'Iraq',
  'Ireland': 'Ireland',
  'Israel': 'Israel',
  'Italy': 'Italy',
  'Jamaica': 'Jamaica',
  'Japan': 'Japan',
  'Jordan': 'Jordan',
  'Kazakhstan': 'Kazakhstan',
  'Kenya': 'Kenya',
  'Kuwait': 'Kuwait',
  'Kyrgyzstan': 'Kyrgyzstan',
  'Laos': 'Laos',
  'Latvia': 'Latvia',
  'Lebanon': 'Lebanon',
  'Lithuania': 'Lithuania',
  'Luxembourg': 'Luxembourg',
  'Madagascar': 'Madagascar',
  'Malaysia': 'Malaysia',
  'Mexico': 'Mexico',
  'Mongolia': 'Mongolia',
  'Morocco': 'Morocco',
  'Myanmar': 'Myanmar',
  'Nepal': 'Nepal',
  'Netherlands': 'Netherlands',
  'New Zealand': 'New Zealand',
  'Nigeria': 'Nigeria',
  'North Korea': 'North Korea',
  'Norway': 'Norway',
  'Oman': 'Oman',
  'Pakistan': 'Pakistan',
  'Panama': 'Panama',
  'Paraguay': 'Paraguay',
  'Peru': 'Peru',
  'Philippines': 'Philippines',
  'Poland': 'Poland',
  'Portugal': 'Portugal',
  'Qatar': 'Qatar',
  'Romania': 'Romania',
  'Russia': 'Russia',
  'Saudi Arabia': 'Saudi Arabia',
  'Serbia': 'Serbia',
  'Singapore': 'Singapore',
  'Slovakia': 'Slovakia',
  'Slovenia': 'Slovenia',
  'South Africa': 'South Africa',
  'South Korea': 'South Korea',
  'Spain': 'Spain',
  'Sri Lanka': 'Sri Lanka',
  'Sudan': 'Sudan',
  'Sweden': 'Sweden',
  'Switzerland': 'Switzerland',
  'Syria': 'Syria',
  'Taiwan': 'Taiwan',
  'Tajikistan': 'Tajikistan',
  'Tanzania': 'Tanzania',
  'Thailand': 'Thailand',
  'Tunisia': 'Tunisia',
  'Turkey': 'Turkey',
  'Turkmenistan': 'Turkmenistan',
  'Uganda': 'Uganda',
  'Ukraine': 'Ukraine',
  'United Arab Emirates': 'UAE',
  'UAE': 'UAE',
  'United Kingdom': 'UK',
  'UK': 'UK',
  'United States': 'USA',
  'USA': 'USA',
  'Uruguay': 'Uruguay',
  'Uzbekistan': 'Uzbekistan',
  'Venezuela': 'Venezuela',
  'Vietnam': 'Vietnam',
  'Yemen': 'Yemen',
  'Zambia': 'Zambia',
  'Zimbabwe': 'Zimbabwe'
};


// --- NEW ENDPOINT FOR GLOBAL MAP DISTRIBUTION DATA ---
app.get('/api/dashboard/global-distribution', async (req, res) => {
    const { year } = req.query;

    if (!year) {
        return res.status(400).json({ error: 'Year query parameter is required.' });
    }

    try {
        // This is your new, more detailed query integrated into the endpoint.
        const query = `
      SELECT
    nml.fkCountry AS country,
    e.Yr AS year,   -- ✅ include year in result if you want to show it
    SUM(
        CASE
            WHEN nml.Detail LIKE '%Pratishtha%'
              OR nml.Detail LIKE '%Sthapna%'
              OR nml.SubDetail LIKE '%Pratishtha%'
              OR nml.SubDetail LIKE '%Sthapna%'
            THEN 1 ELSE 0 END
    ) AS pratishthas,
    SUM(
        CASE
            WHEN nml.Detail LIKE '%Padhramani%'
              OR nml.Detail LIKE '%Pagla%'
              OR nml.SubDetail LIKE '%Padhramani%'
              OR nml.SubDetail LIKE '%Pagla%'
            THEN 1 ELSE 0 END
    ) AS padhramanis
FROM Events AS e
INNER JOIN DigitalRecordings AS dr
    ON e.EventCode = dr.fkEventCode
INNER JOIN NewMediaLog AS nml
    ON dr.RecordingCode = nml.fkDigitalRecordingCode
WHERE
    e.Yr = ?                          -- ✅ filter by selected year
    AND nml.FootageType <> 'Glimpses'
    AND nml.EditingStatus NOT LIKE '%title%'
    AND dr.PreservationStatus = 'Preserve'
    AND nml.fkCountry IS NOT NULL
    AND nml.fkCountry <> ''
GROUP BY
    nml.fkCountry, e.Yr
ORDER BY
    country ASC;

        `;

        const [results] = await db.query(query, [year]);

        // Post-process to add coordinates and format for the frontend
        // This part is crucial for compatibility with your React component
        const dataWithCoords = results.map(row => {
            const normalizedName = countryNameMapping[row.country] || row.country;
            return {
                name: normalizedName,
                pratishthas: row.pratishthas,
                padhramanis: row.padhramanis,
                lat: countryCoordinates[normalizedName]?.lat || 0,
                lng: countryCoordinates[normalizedName]?.lng || 0,
            };
        }).filter(country => country.lat !== 0 || country.lng !== 0);

        res.json(dataWithCoords);
    } catch (err) {
        console.error("Database query error on /api/dashboard/global-distribution:", err);
        res.status(500).json({ error: 'Failed to fetch global distribution data' });
    }
});



// in src/server/index.js

// --- NEW ENDPOINT: Fetch only Pratishtha events for a country and year ---
app.get('/api/dashboard/pratishtha-events', async (req, res) => {
    const { year, country } = req.query;

    if (!year || !country) {
        return res.status(400).json({ error: 'Year and Country are required.' });
    }

    try {
        // Using the query you provided
        const query = `
          SELECT
    e.EventCode,
    e.EventName,
    e.FromDate,
    e.ToDate,
    nml.fkCity,
    GROUP_CONCAT(DISTINCT nml.Detail ORDER BY nml.Detail SEPARATOR ', ') AS ContentDetails
FROM Events AS e
INNER JOIN DigitalRecordings AS dr
    ON e.EventCode = dr.fkEventCode
INNER JOIN NewMediaLog AS nml
    ON dr.RecordingCode = nml.fkDigitalRecordingCode
WHERE e.Yr = ?
  AND nml.fkCountry = ?
  AND (
       nml.Detail LIKE '%Pratishtha%'
    OR nml.Detail LIKE '%Sthapna%'
    OR nml.SubDetail LIKE '%Pratishtha%'
    OR nml.SubDetail LIKE '%Sthapna%'
  )
GROUP BY e.EventCode, e.EventName, e.FromDate, e.ToDate, nml.fkCity
ORDER BY e.FromDate ASC;

        `;
        const [results] = await db.query(query, [year, country]);
        res.json(results);
    } catch (err) {
        console.error("Database query error on /pratishtha-events:", err);
        res.status(500).json({ error: 'Failed to fetch Pratishtha events' });
    }
});

// --- NEW ENDPOINT: Fetch only Padhramani events for a country and year ---
app.get('/api/dashboard/padhramani-events', async (req, res) => {
    const { year, country } = req.query;

    if (!year || !country) {
        return res.status(400).json({ error: 'Year and Country are required.' });
    }

    try {
        // Using the query you provided
        const query = `
           SELECT
                e.EventCode,
                e.EventName,
                e.FromDate,
                e.ToDate,
                nml.fkCity,
                GROUP_CONCAT(DISTINCT nml.Detail ORDER BY nml.Detail SEPARATOR ', ') AS ContentDetails
            FROM Events AS e
            INNER JOIN DigitalRecordings AS dr
                ON e.EventCode = dr.fkEventCode
            INNER JOIN NewMediaLog AS nml
                ON dr.RecordingCode = nml.fkDigitalRecordingCode
            WHERE e.Yr = ?
              AND nml.fkCountry = ?
              AND (
                   nml.Detail LIKE '%Padhramani%'
                OR nml.Detail LIKE '%Pagla%'
                OR nml.SubDetail LIKE '%Padhramani%'
                OR nml.SubDetail LIKE '%Pagla%'
              )
            GROUP BY e.EventCode, e.EventName, e.FromDate, e.ToDate, nml.fkCity
            ORDER BY e.FromDate ASC;
        `;
        const [results] = await db.query(query, [year, country]);
        res.json(results);
    } catch (err) {
        console.error("Database query error on /padhramani-events:", err);
        res.status(500).json({ error: 'Failed to fetch Padhramani events' });
    }
});




// in src/server/index.js

// --- ADD THIS NEW ENDPOINT for the grouped event view ---
app.get('/api/dashboard/events-by-group', async (req, res) => {
    const { year, country, city } = req.query;

    if (!year || (!country && !city)) {
        return res.status(400).json({ error: 'Year and either Country or City are required.' });
    }

    try {
        let whereClause = 'e.Yr = ?';
        const params = [year];

        if (country) {
            whereClause += ' AND nml.fkCountry = ?';
            params.push(country);
        } else { // city must be present
            whereClause += ' AND nml.fkCity = ?';
            params.push(city);
        }

        const query = `
            SELECT
                e.EventCode,
                e.EventName,
                e.FromDate,
                e.ToDate,
                nml.fkCity,
                nml.fkCountry,
                COUNT(nml.MLUniqueID) AS ContentCount
            FROM Events AS e
            INNER JOIN DigitalRecordings AS dr ON e.EventCode = dr.fkEventCode
            INNER JOIN NewMediaLog AS nml ON dr.RecordingCode = nml.fkDigitalRecordingCode
            WHERE ${whereClause}
            GROUP BY 
                e.EventCode, e.EventName, e.FromDate, e.ToDate, nml.fkCity, nml.fkCountry
            ORDER BY 
                e.FromDate ASC;
        `;
        
        const [results] = await db.query(query, params);
        res.json(results);

    } catch (err) {
        console.error("Database query error on /api/dashboard/events-by-group:", err);
        res.status(500).json({ error: 'Failed to fetch grouped event data' });
    }
});

app.get('/api/dashboard/pratishtha-events-by-group', async (req, res) => {
    const { year, country } = req.query;

    if (!year || !country) {
        return res.status(400).json({ error: 'Year and Country are required.' });
    }

    try {
        const query = `
            SELECT
                e.EventCode,
                e.EventName,
                e.FromDate,
                e.ToDate,
                nml.fkCity,
                nml.fkCountry,
                COUNT(nml.MLUniqueID) AS ContentCount
            FROM Events AS e
            INNER JOIN DigitalRecordings AS dr ON e.EventCode = dr.fkEventCode
            INNER JOIN NewMediaLog AS nml ON dr.RecordingCode = nml.fkDigitalRecordingCode
            WHERE e.Yr = ? 
              AND nml.fkCountry = ? 
              AND e.EventName LIKE '%Pratishtha%'
            GROUP BY 
                e.EventCode, e.EventName, e.FromDate, e.ToDate, nml.fkCity, nml.fkCountry
            ORDER BY 
                e.FromDate ASC;
        `;
        
        const [results] = await db.query(query, [year, country]);
        res.json(results);

    } catch (err) {
        console.error("Database query error on /api/dashboard/pratishtha-events-by-group:", err);
        res.status(500).json({ error: 'Failed to fetch grouped Pratishtha event data' });
    }
});

// --- NEW ENDPOINT 2: Grouped Padhramani Events ---
app.get('/api/dashboard/padhramani-events-by-group', async (req, res) => {
    const { year, country } = req.query;

    if (!year || !country) {
        return res.status(400).json({ error: 'Year and Country are required.' });
    }

    try {
        const query = `
            SELECT
                e.EventCode,
                e.EventName,
                e.FromDate,
                e.ToDate,
                nml.fkCity,
                nml.fkCountry,
                COUNT(nml.MLUniqueID) AS ContentCount
            FROM Events AS e
            INNER JOIN DigitalRecordings AS dr ON e.EventCode = dr.fkEventCode
            INNER JOIN NewMediaLog AS nml ON dr.RecordingCode = nml.fkDigitalRecordingCode
            WHERE e.Yr = ? 
              AND nml.fkCountry = ? 
              AND e.EventName LIKE '%Padhramani%'
            GROUP BY 
                e.EventCode, e.EventName, e.FromDate, e.ToDate, nml.fkCity, nml.fkCountry
            ORDER BY 
                e.FromDate ASC;
        `;
        
        const [results] = await db.query(query, [year, country]);
        res.json(results);

    } catch (err) {
        console.error("Database query error on /api/dashboard/padhramani-events-by-group:", err);
        res.status(500).json({ error: 'Failed to fetch grouped Padhramani event data' });
    }
});

// --- Send Invitation Endpoint ---
app.post("/api/send-invitation", async (req, res) => {
  const { email, role, teams, message, appLink } = req.body;

  if (!email) {
    return res.status(400).json({ message: "Recipient email is required." });
  }

  try {
    const transporter = await createTransporter();

    const mailOptions = {
      from: "your-email@gmail.com", // Your Gmail address
      to: email,
      subject: "You're Invited to Join Our App!",
      html: `
        <p>Hello,</p>
        <p>You have been invited to join our app as a <strong>${role}</strong>.</p>
        <p>Teams: ${teams.join(", ") || "None"}</p>
        <p>${message || ""}</p>
        <p><a href="${appLink}" target="_blank">Click here to join</a></p>
        <p>Best regards,<br>Your App Team</p>
      `,
    };

    await transporter.sendMail(mailOptions);

    res.status(200).json({ message: "Invitation sent successfully." });
  } catch (error) {
    console.error("Error sending email:", error);
    res.status(500).json({ message: "Failed to send invitation." });
  }
});

// OAuth2 Configuration

const createTransporter = async () => {
  const oauth2Client = new google.auth.OAuth2(
    process.env.CLIENT_ID,
    process.env.CLIENT_SECRET,
    process.env.REDIRECT_URI || "https://developers.google.com/oauthplayground"
  );

  oauth2Client.setCredentials({ refresh_token: process.env.REFRESH_TOKEN });

  const accessToken = await oauth2Client.getAccessToken();

  return nodemailer.createTransport({
    service: "Gmail",
    auth: {
      type: "OAuth2",
      user: process.env.EMAIL_USER, // Your Gmail address
      clientId: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      refreshToken: process.env.REFRESH_TOKEN,
      accessToken: accessToken.token,
    },
  });
};

// Google Sheets setup
const SHEET_ID = "1GaCTwU_LUFF2B9NbBVzenwRjrW8sPvUJMkKzDUOdme0";
const credentials = {
  type: process.env.SERVICE_ACCOUNT_TYPE,
  project_id: process.env.SERVICE_ACCOUNT_PROJECT_ID,
  private_key_id: process.env.SERVICE_ACCOUNT_PRIVATE_KEY_ID,
  private_key: process.env.SERVICE_ACCOUNT_PRIVATE_KEY.replace(/\\n/g, '\n'), // Replace escaped newlines
  client_email: process.env.SERVICE_ACCOUNT_CLIENT_EMAIL,
  client_id: process.env.SERVICE_ACCOUNT_CLIENT_ID,
  auth_uri: process.env.SERVICE_ACCOUNT_AUTH_URI,
  token_uri: process.env.SERVICE_ACCOUNT_TOKEN_URI,
  auth_provider_x509_cert_url: process.env.SERVICE_ACCOUNT_AUTH_PROVIDER_CERT_URL,
  client_x509_cert_url: process.env.SERVICE_ACCOUNT_CLIENT_CERT_URL,
};

const auth = new google.auth.GoogleAuth({
  credentials,
  scopes: ["https://www.googleapis.com/auth/spreadsheets"],
});


// --- Helper Functions for Permissions ---


// --- Helper Functions for Permissions (Your Original Code) ---
const parsePermissions = (permissionString) => {
  if (!permissionString || typeof permissionString !== 'string') return [];
  try {
    return permissionString.split(';').map(p => {
      const [resource, actionsStr] = p.split(':');
      if (!resource || !actionsStr) return null;
      return { resource, actions: actionsStr.split(',') };
    }).filter(Boolean);
  } catch (e) {
    console.error("Could not parse permissions string:", permissionString, e);
    return [];
  }
};

const formatPermissions = (permissionsArray) => {
    if (!permissionsArray || permissionsArray.length === 0) return "";
    return permissionsArray.map(p => `${p.resource}:${p.actions.join(',')}`).join(';');
};


// ===================================================================================
// --- API ENDPOINTS ---
// ===================================================================================

// --- GET ALL USERS ---
app.get("/api/users", async (_req, res) => {
  try {
    const sheets = google.sheets({ version: "v4", auth: await auth.getClient() });
    const result = await sheets.spreadsheets.values.get({
      spreadsheetId: SHEET_ID,
      // Read all columns from A to K to include permissions
      range: "Sheet1!A2:K", 
    });

    const users = (result.data.values || []).map(row => ({
      id: row[0],
      name: row[1],
      email: row[2],
      role: row[3],
      status: row[4],
      joinedDate: row[5],
      lastActive: row[6],
      teams: row[7] ? row[7].split(",") : [],
      department: row[8],
      location: row[9],
      permissions: parsePermissions(row[10]) // Parse from Column K (index 10)
    }));
    res.json(users);
  } catch (err) {
    console.error("Error fetching users from Google Sheet:", err);
    res.status(500).json({ error: "Failed to fetch user data." });
  }
});

// --- ADD A NEW USER ---
app.post("/api/users", async (req, res) => {
  const { name, email, role, department, location, teams, permissions } = req.body;

  if (!name || !email || !role) {
    return res.status(400).json({ error: "Name, email, and role are required." });
  }

  try {
    const sheets = google.sheets({ version: "v4", auth: await auth.getClient() });

    const now = new Date();
    const newId = now.getTime().toString();
    const joinedDate = now.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
    const status = 'Active';
    const lastActive = now.toISOString();

    // Ensure teams and permissions are properly formatted
    const formattedTeams = Array.isArray(teams) ? teams : [];
    const formattedPermissions = permissions || [];

    // Order must match your Google Sheet columns: A, B, C... K
    const newRow = [
      newId,
      name,
      email,
      role,
      status,
      joinedDate,
      lastActive,
      formattedTeams.join(','), // Convert teams array to a comma-separated string
      department || '',
      location || '',
      formatPermissions(formattedPermissions), // Save the formatted string to Column K
    ];

    await sheets.spreadsheets.values.append({
      spreadsheetId: SHEET_ID,
      range: "Sheet1!A:K",
      valueInputOption: "USER_ENTERED",
      resource: {
        values: [newRow],
      },
    });

    const createdUser = {
      id: newId,
      name,
      email,
      role,
      status,
      joinedDate,
      lastActive,
      teams: formattedTeams,
      department,
      location,
      permissions: formattedPermissions,
    };

    res.status(201).json(createdUser);
  } catch (err) {
    console.error("Error adding user to Google Sheet:", err);
    res.status(500).json({ error: "Failed to add user." });
  }
});

// --- DELETE A USER ---
app.delete('/api/users/:id', async (req, res) => {
  const { id } = req.params;

  if (!id) {
    return res.status(400).json({ error: "User ID is required." });
  }

  try {
    const sheets = google.sheets({ version: "v4", auth: await auth.getClient() });

    // Get the sheet metadata to retrieve the sheetId dynamically
    const sheetMetadata = await sheets.spreadsheets.get({
      spreadsheetId: SHEET_ID,
    });
    const sheetId = sheetMetadata.data.sheets[0].properties.sheetId;

    // Fetch all rows in the first column (IDs)
    const getRowsResponse = await sheets.spreadsheets.values.get({
      spreadsheetId: SHEET_ID,
      range: 'Sheet1!A:A', 
    });

    const ids = getRowsResponse.data.values;
    if (!ids || ids.length === 0) {
      return res.status(404).json({ error: "Sheet is empty, user not found." });
    }

    // Skip the header row and find the user ID
    const rowIndexToDelete = ids.slice(1).findIndex(row => row[0] === id);

    if (rowIndexToDelete === -1) {
      return res.status(404).json({ error: "User not found." });
    }

    // Adjust the index to account for the skipped header row
    const adjustedRowIndex = rowIndexToDelete + 1;

    // Delete the row
    const batchUpdateRequest = {
      requests: [{
        deleteDimension: {
          range: {
            sheetId: sheetId,
            dimension: 'ROWS',
            startIndex: adjustedRowIndex,
            endIndex: adjustedRowIndex + 1,
          },
        },
      }],
    };

    await sheets.spreadsheets.batchUpdate({
      spreadsheetId: SHEET_ID,
      resource: batchUpdateRequest,
    });

    res.status(200).json({ message: 'User deleted successfully.' });
  } catch (err) {
    console.error("Error deleting user from Google Sheet:", err);
    res.status(500).json({ error: "Failed to delete user." });
  }
});

// --- UPDATE USER PERMISSIONS ---
app.put('/api/users/:id/permissions', async (req, res) => {
  const { id } = req.params;
  const { permissions } = req.body;

  if (!id || !permissions) {
    return res.status(400).json({ error: "User ID and permissions array are required." });
  }

  try {
    const sheets = google.sheets({ version: "v4", auth: await auth.getClient() });

    const getRowsResponse = await sheets.spreadsheets.values.get({
      spreadsheetId: SHEET_ID,
      range: 'Sheet1!A:A',
    });

    const ids = getRowsResponse.data.values;
    // We start searching from index 1 to skip the header row.
    const rowIndex = ids.slice(1).findIndex(row => row[0] === id); 

    if (rowIndex === -1) {
      return res.status(404).json({ error: "User not found." });
    }

    const permissionsString = formatPermissions(permissions);
    
    // rowIndex is 0-based from the data (A2 onwards), but sheet ranges are 1-based.
    // So, we need to add 2 to get the correct sheet row number (1 for header, 1 for 0-indexing).
    const sheetRowNumber = rowIndex + 2; 

    await sheets.spreadsheets.values.update({
      spreadsheetId: SHEET_ID,
      range: `Sheet1!K${sheetRowNumber}`, // Update cell in Column K for the correct row
      valueInputOption: 'USER_ENTERED',
      resource: {
        values: [[permissionsString]],
      },
    });

    res.status(200).json({ message: 'Permissions updated successfully.' });
  } catch (err) {
    console.error("Error updating permissions:", err);
    res.status(500).json({ error: "Failed to update permissions." });
  }
});


// ✅ THIS IS THE MODIFIED ENDPOINT
app.get('/api/users/by-email/:email', async (req, res) => {
  const userEmailToFind = req.params.email;

  if (!userEmailToFind) {
    return res.status(400).json({ error: "Email parameter is required." });
  }

  try {
    const sheets = google.sheets({ version: "v4", auth: await auth.getClient() });
    const result = await sheets.spreadsheets.values.get({
      spreadsheetId: SHEET_ID,
      range: "Sheet1!A2:K", // Ensure you are reading up to column K for permissions
    });

    const rows = result.data.values || [];
    const userRow = rows.find(row => row[2] && row[2].toLowerCase() === userEmailToFind.toLowerCase());

    if (userRow) {
      const user = {
        id: userRow[0],
        name: userRow[1],
        email: userRow[2],
        role: userRow[3],
        permissions: parsePermissions(userRow[10]), // Parse permissions from column K
      };

      console.log(`✅ Authentication successful for: ${userEmailToFind}`);
      res.status(200).json(user);
    } else {
      console.log(`❌ Authentication failed. User not found: ${userEmailToFind}`);
      res.status(404).json({ error: 'User not found in application registry. Please contact admin.' });
    }
  } catch (err) {
    console.error("Error looking up user by email from Google Sheet:", err);
    res.status(500).json({ error: "Failed to verify user." });
  }
});


// --- NEW ENDPOINT FOR 'AudioList' DROPDOWN ---
app.get('/api/audio/options', async (req, res) => {
  try {
    const query = `
      SELECT DISTINCT 
        AudioList 
      FROM Audio 
      WHERE AudioList IS NOT NULL AND AudioList <> ''
      ORDER BY AudioList ASC
    `;
    const [results] = await db.query(query);
    res.status(200).json(results);
  } catch (err) {
    console.error("❌ Database query error on /api/audio/options:", err);
    res.status(500).json({ error: 'Failed to fetch audio list options.' });
  }
});
// --- Endpoint to fetch data from the "Audio" table ---
app.get('/api/audio', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1; // Default to page 1
    const limit = parseInt(req.query.limit) || 50; // Default to 50 items per page
    const offset = (page - 1) * limit;

    const filterableColumns = [
      'AID',
      'AudioList',
      'Distribution',
      'LastModifiedTimestamp',
    ];

    const { whereString, params } = buildWhereClause(
      req.query,
      ['AID', 'AudioList', 'Distribution'], // Searchable fields
      filterableColumns
    );

    const orderByString = buildOrderByClause(req.query, filterableColumns);

    // --- Count Query ---
    const countQuery = `SELECT COUNT(*) as total FROM Audio ${whereString}`;
    const [[{ total }]] = await db.query(countQuery, params);
    const totalPages = Math.ceil(total / limit);

    // --- Data Query ---
    const dataQuery = `
      SELECT * 
      FROM Audio 
      ${whereString} 
      ${orderByString} 
      LIMIT ? OFFSET ?
    `;
    const [results] = await db.query(dataQuery, [...params, limit, offset]);

    res.json({
      data: results,
      pagination: {
        page,
        limit,
        totalItems: total,
        totalPages,
      },
    });
  } catch (err) {
    console.error("❌ Database query error on /api/audio:", err);
    res.status(500).json({ error: 'Failed to fetch audio data' });
  }
});

app.get('/api/audio/export', async (req, res) => {
  try {
    const { whereString, params } = buildWhereClause(
      req.query,
      ['AID', 'AudioList', 'Distribution'], // Searchable fields
      ['AID', 'AudioList', 'Distribution', 'LastModifiedTimestamp'] // Filterable columns
    );

    const dataQuery = `SELECT * FROM Audio ${whereString}`;
    const [results] = await db.query(dataQuery, params);

    if (results.length === 0) {
      return res.status(404).send("No data found to export for the given filters.");
    }

    const headers = Object.keys(results[0]);
    const csvHeader = headers.join(',');
    const csvRows = results.map(row =>
      headers.map(header => {
        const value = row[header];
        const strValue = String(value === null || value === undefined ? '' : value);
        return `"${strValue.replace(/"/g, '""')}"`;
      }).join(',')
    );
    const csvContent = [csvHeader, ...csvRows].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="audio_export.csv"');
    res.status(200).send(csvContent);
  } catch (err) {
    console.error("❌ Database query error on /api/audio/export:", err);
    res.status(500).json({ error: 'CSV export failed' });
  }
});

app.put('/api/audio/:AID', async (req, res) => {
  const { AID } = req.params;
  const { AudioList, Distribution, LastModifiedBy } = req.body;

  if (!AID) {
    return res.status(400).json({ error: "Audio ID (AID) is required." });
  }

  try {
    const query = `
      UPDATE Audio
      SET
        AudioList = ?,
        Distribution = ?,
        LastModifiedBy = ?,
        LastModifiedTimestamp = NOW()
      WHERE AID = ?
    `;

    const [result] = await db.query(query, [
      AudioList, Distribution, LastModifiedBy || '', AID
    ]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: `Audio with ID ${AID} not found.` });
    }

    res.status(200).json({ message: "Audio updated successfully." });
  } catch (err) {
    console.error("❌ Database query error on /api/audio/:AID:", err);
    res.status(500).json({ error: "Failed to update Audio." });
  }
});

app.post('/api/audio', async (req, res) => {
  const { AudioList, Distribution, LastModifiedBy } = req.body;

  if (!AudioList) {
    return res.status(400).json({ error: "AudioList is required." });
  }
  if (!Distribution) {
    return res.status(400).json({ error: "Distribution is required." });
  }
  if (!LastModifiedBy) {
    return res.status(400).json({ error: "LastModifiedBy (user email) is required." });
  }

  try {
    const query = `
      INSERT INTO Audio (AudioList, Distribution, LastModifiedBy, LastModifiedTimestamp)
      VALUES (?, ?, ?, NOW())
    `;
    const [result] = await db.query(query, [AudioList, Distribution, LastModifiedBy]);

    res.status(201).json({
      message: "Audio record added successfully.",
      AID: result.insertId,
      AudioList,
      Distribution,
      LastModifiedBy,
      LastModifiedTimestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error("❌ Database query error on POST /api/audio:", err);
    res.status(500).json({ error: "Failed to add Audio record." });
  }
});

// --- NEW ENDPOINT FOR 'BhajanName' DROPDOWN ---
app.get('/api/bhajan-type/options', async (req, res) => {
  try {
    // 1. Fetch all non-empty, distinct BhajanType strings from the NewMediaLog table.
    const query = `
      SELECT DISTINCT BhajanType
      FROM NewMediaLog
      WHERE BhajanType IS NOT NULL AND TRIM(BhajanType) <> ''
    `;
    const [rows] = await db.query(query);

    // 2. Process the results to get individual unique values.
    const allTypes = new Set();
    rows.forEach(row => {
      if (row.BhajanType) {
        row.BhajanType.split(',')
          .map(t => t.trim())
          .filter(t => t !== '')
          .forEach(t => allTypes.add(t));
      }
    });

    // 3. Convert the Set to a sorted array of objects for the frontend.
    const uniqueTypes = Array.from(allTypes).sort();
    const results = uniqueTypes.map(t => ({ BhajanType: t }));

    res.status(200).json(results);
  } catch (err) {
    console.error("❌ Database query error on /api/bhajan-type/options:", err);
    res.status(500).json({ error: 'Failed to fetch Bhajan Name options.' });
  }
});

app.get('/api/bhajan-type', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1; // Default to page 1
    const limit = parseInt(req.query.limit) || 50; // Default to 50 items per page
    const offset = (page - 1) * limit;

    const filterableColumns = [
      'BTID',
      'BhajanName',
      'LastModifiedTimestamp',
    ];

    const { whereString, params } = buildWhereClause(
      req.query,
      ['BTID', 'BhajanName'], // Searchable fields
      filterableColumns
    );

    const orderByString = buildOrderByClause(req.query, filterableColumns);

    // --- Count Query ---
    const countQuery = `SELECT COUNT(*) as total FROM BhajanTypes ${whereString}`;
    const [[{ total }]] = await db.query(countQuery, params);
    const totalPages = Math.ceil(total / limit);

    // --- Data Query ---
    const dataQuery = `
      SELECT * 
      FROM BhajanTypes 
      ${whereString} 
      ${orderByString} 
      LIMIT ? OFFSET ?
    `;
    const [results] = await db.query(dataQuery, [...params, limit, offset]);

    res.json({
      data: results,
      pagination: {
        page,
        limit,
        totalItems: total,
        totalPages,
      },
    });
  } catch (err) {
    console.error("❌ Database query error on /api/bhajan-type:", err);
    res.status(500).json({ error: 'Failed to fetch Bhajan Type data' });
  }
});

app.get('/api/bhajan-type/export', async (req, res) => {
  try {
    const { whereString, params } = buildWhereClause(
      req.query,
      ['BTID', 'BhajanName'], // Searchable fields
      ['BTID', 'BhajanName', 'LastModifiedTimestamp'] // Filterable columns
    );

    const dataQuery = `SELECT * FROM BhajanTypes ${whereString}`;
    const [results] = await db.query(dataQuery, params);

    if (results.length === 0) {
      return res.status(404).send("No data found to export for the given filters.");
    }

    const headers = Object.keys(results[0]);
    const csvHeader = headers.join(',');
    const csvRows = results.map(row =>
      headers.map(header => {
        const value = row[header];
        const strValue = String(value === null || value === undefined ? '' : value);
        return `"${strValue.replace(/"/g, '""')}"`;
      }).join(',')
    );
    const csvContent = [csvHeader, ...csvRows].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="bhajan_type_export.csv"');
    res.status(200).send(csvContent);
  } catch (err) {
    console.error("❌ Database query error on /api/bhajan-type/export:", err);
    res.status(500).json({ error: 'CSV export failed' });
  }
});

app.put('/api/bhajantype/:BTID', async (req, res) => {
  const { BTID } = req.params;
  const { BhajanName, LastModifiedBy } = req.body;

  if (!BTID) {
    return res.status(400).json({ error: "Bhajan Type ID (BTID) is required." });
  }
  if (!BhajanName) {
    return res.status(400).json({ error: "BhajanName is required." });
  }
  if (!LastModifiedBy) {
    return res.status(400).json({ error: "LastModifiedBy (user email) is required." });
  }

  try {
    const query = `
      UPDATE BhajanTypes
      SET BhajanName = ?, LastModifiedBy = ?, LastModifiedTimestamp = NOW()
      WHERE BTID = ?
    `;

    const [result] = await db.query(query, [BhajanName, LastModifiedBy, BTID]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: `Bhajan Type with ID ${BTID} not found.` });
    }

    res.status(200).json({ message: "BhajanName updated successfully." });
  } catch (err) {
    console.error("❌ Database query error on /api/bhajantype/:BTID:", err);
    res.status(500).json({ error: "Failed to update BhajanName." });
  }
});

app.post('/api/bhajan-type', async (req, res) => {
  const { BhajanName, LastModifiedBy } = req.body;

  if (!BhajanName) {
    return res.status(400).json({ error: "BhajanName is required." });
  }
  if (!LastModifiedBy) {
    return res.status(400).json({ error: "LastModifiedBy (user email) is required." });
  }

  try {
    const query = `
      INSERT INTO BhajanTypes (BhajanName, LastModifiedBy, LastModifiedTimestamp)
      VALUES (?, ?, NOW())
    `;
    const [result] = await db.query(query, [BhajanName, LastModifiedBy]);

    res.status(201).json({
      message: "Bhajan Type added successfully.",
      BTID: result.insertId,
      BhajanName,
      LastModifiedBy,
      LastModifiedTimestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error("❌ Database query error on POST /api/bhajan-type:", err);
    res.status(500).json({ error: "Failed to add Bhajan Type." });
  }
});
// --- NEW ENDPOINT FOR 'fkDigitalMasterCategory' DROPDOWN ---
app.get('/api/digital-master-category/options', async (req, res) => {
  try {
    // 1. Fetch all non-empty, distinct fkDigitalMasterCategory strings from the DigitalRecordings table.
    const query = `
      SELECT DISTINCT fkDigitalMasterCategory
      FROM DigitalRecordings
      WHERE fkDigitalMasterCategory IS NOT NULL AND TRIM(fkDigitalMasterCategory) <> ''
    `;
    const [rows] = await db.query(query);

    // 2. Process the results to get individual unique values.
    const allCategories = new Set();
    rows.forEach(row => {
      if (row.fkDigitalMasterCategory) {
        row.fkDigitalMasterCategory.split(',')
          .map(c => c.trim())
          .filter(c => c !== '')
          .forEach(c => allCategories.add(c));
      }
    });

    // 3. Convert the Set to a sorted array of objects for the frontend.
    const uniqueCategories = Array.from(allCategories).sort();
    const results = uniqueCategories.map(c => ({ fkDigitalMasterCategory: c }));

    res.status(200).json(results);
  } catch (err) {
    console.error("❌ Database query error on /api/digital-master-category/options:", err);
    res.status(500).json({ error: 'Failed to fetch digital master category options.' });
  }
});

app.get('/api/digital-master-category', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1; // Default to page 1
    const limit = parseInt(req.query.limit) || 50; // Default to 50 items per page
    const offset = (page - 1) * limit;

    const filterableColumns = [
      'DMCID',
      'DMCategory_name',
      'LastModifiedTimestamp',
    ];

    const { whereString, params } = buildWhereClause(
      req.query,
      ['DMCID', 'DMCategory_name'], // Searchable fields
      filterableColumns
    );

    const orderByString = buildOrderByClause(req.query, filterableColumns);

    // --- Count Query ---
    const countQuery = `SELECT COUNT(*) as total FROM DigitalMasterCategory ${whereString}`;
    const [[{ total }]] = await db.query(countQuery, params);
    const totalPages = Math.ceil(total / limit);

    // --- Data Query ---
    const dataQuery = `
      SELECT * 
      FROM DigitalMasterCategory 
      ${whereString} 
      ${orderByString} 
      LIMIT ? OFFSET ?
    `;
    const [results] = await db.query(dataQuery, [...params, limit, offset]);

    res.json({
      data: results,
      pagination: {
        page,
        limit,
        totalItems: total,
        totalPages,
      },
    });
  } catch (err) {
    console.error("❌ Database query error on /api/digital-master-category:", err);
    res.status(500).json({ error: 'Failed to fetch Digital Master Category data' });
  }
});

app.get('/api/digital-master-category/export', async (req, res) => {
  try {
    const { whereString, params } = buildWhereClause(
      req.query,
      ['DMCID', 'DMCategory_name'], // Searchable fields
      ['DMCID', 'DMCategory_name', 'LastModifiedTimestamp'] // Filterable columns
    );

    const dataQuery = `SELECT * FROM DigitalMasterCategory ${whereString}`;
    const [results] = await db.query(dataQuery, params);

    if (results.length === 0) {
      return res.status(404).send("No data found to export for the given filters.");
    }

    const headers = Object.keys(results[0]);
    const csvHeader = headers.join(',');
    const csvRows = results.map(row =>
      headers.map(header => {
        const value = row[header];
        const strValue = String(value === null || value === undefined ? '' : value);
        return `"${strValue.replace(/"/g, '""')}"`;
      }).join(',')
    );
    const csvContent = [csvHeader, ...csvRows].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="digital_master_category_export.csv"');
    res.status(200).send(csvContent);
  } catch (err) {
    console.error("❌ Database query error on /api/digital-master-category/export:", err);
    res.status(500).json({ error: 'CSV export failed' });
  }
});

app.put('/api/digitalmastercategory/:DMCID', async (req, res) => {
  const { DMCID } = req.params;
  const { DMCategory_name, LastModifiedBy } = req.body;

  if (!DMCID) {
    return res.status(400).json({ error: "DMCID is required." });
  }
  if (!DMCategory_name) {
    return res.status(400).json({ error: "DMCategory_name is required." });
  }
  if (!LastModifiedBy) {
    return res.status(400).json({ error: "LastModifiedBy (user email) is required." });
  }

  try {
    const query = `
      UPDATE DigitalMasterCategory
      SET DMCategory_name = ?, LastModifiedBy = ?, LastModifiedTimestamp = NOW()
      WHERE DMCID = ?
    `;
    const [result] = await db.query(query, [DMCategory_name, LastModifiedBy, DMCID]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: `Digital Master Category with ID ${DMCID} not found.` });
    }
    res.status(200).json({ message: "DMCategory_name updated successfully." });
  } catch (err) {
    console.error("❌ Database query error on /api/digital-master-category/:DMCID:", err);
    res.status(500).json({ error: "Failed to update DMCategory_name." });
  }
});

app.post('/api/digital-master-category', async (req, res) => {
  const { DMCategory_name, LastModifiedBy } = req.body;

  if (!DMCategory_name) {
    return res.status(400).json({ error: "DMCategory_name is required." });
  }
  if (!LastModifiedBy) {
    return res.status(400).json({ error: "LastModifiedBy (user email) is required." });
  }

  try {
    const query = `
      INSERT INTO DigitalMasterCategory (DMCategory_name, LastModifiedBy, LastModifiedTimestamp)
      VALUES (?, ?, NOW())
    `;
    const [result] = await db.query(query, [DMCategory_name, LastModifiedBy]);

    res.status(201).json({
      message: "Digital Master Category added successfully.",
      DMCID: result.insertId,
      DMCategory_name,
      LastModifiedBy,
      LastModifiedTimestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error("❌ Database query error on POST /api/digital-master-category:", err);
    res.status(500).json({ error: "Failed to add Digital Master Category." });
  }
});
// --- NEW ENDPOINT FOR 'fkDistributionLabel' DROPDOWN ---
app.get('/api/distribution-label/options', async (req, res) => {
  try {
    // 1. Fetch all non-empty, distinct fkDistributionLabel strings from the DigitalRecordings table.
    const query = `
      SELECT DISTINCT fkDistributionLabel
      FROM DigitalRecordings
      WHERE fkDistributionLabel IS NOT NULL AND TRIM(fkDistributionLabel) <> ''
    `;
    const [rows] = await db.query(query);

    // 2. Process the results to get individual unique values.
    const allLabels = new Set();
    rows.forEach(row => {
      if (row.fkDistributionLabel) {
        row.fkDistributionLabel.split(',')
          .map(l => l.trim())
          .filter(l => l !== '')
          .forEach(l => allLabels.add(l));
      }
    });

    // 3. Convert the Set to a sorted array of objects for the frontend.
    const uniqueLabels = Array.from(allLabels).sort();
    const results = uniqueLabels.map(l => ({ fkDistributionLabel: l }));

    res.status(200).json(results);
  } catch (err) {
    console.error("❌ Database query error on /api/distribution-label/options:", err);
    res.status(500).json({ error: 'Failed to fetch distribution label options.' });
  }
});

app.get('/api/distribution-label', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1; // Default to page 1
    const limit = parseInt(req.query.limit) || 50; // Default to 50 items per page
    const offset = (page - 1) * limit;

    const filterableColumns = [
      'LabelID',
      'LabelName',
      'LastModifiedTimestamp',
    ];

    const { whereString, params } = buildWhereClause(
      req.query,
      ['LabelID', 'LabelName'], // Searchable fields
      filterableColumns
    );

    const orderByString = buildOrderByClause(req.query, filterableColumns);

    // --- Count Query ---
    const countQuery = `SELECT COUNT(*) as total FROM DistributionLabel ${whereString}`;
    const [[{ total }]] = await db.query(countQuery, params);
    const totalPages = Math.ceil(total / limit);

    // --- Data Query ---
    const dataQuery = `
      SELECT * 
      FROM DistributionLabel 
      ${whereString} 
      ${orderByString} 
      LIMIT ? OFFSET ?
    `;
    const [results] = await db.query(dataQuery, [...params, limit, offset]);

    res.json({
      data: results,
      pagination: {
        page,
        limit,
        totalItems: total,
        totalPages,
      },
    });
  } catch (err) {
    console.error("❌ Database query error on /api/distribution-label:", err);
    res.status(500).json({ error: 'Failed to fetch Distribution Label data' });
  }
});

app.get('/api/distribution-label/export', async (req, res) => {
  try {
    const { whereString, params } = buildWhereClause(
      req.query,
      ['LabelID', 'LabelName'], // Searchable fields
      ['LabelID', 'LabelName', 'LastModifiedTimestamp'] // Filterable columns
    );

    const dataQuery = `SELECT * FROM DistributionLabel ${whereString}`;
    const [results] = await db.query(dataQuery, params);

    if (results.length === 0) {
      return res.status(404).send("No data found to export for the given filters.");
    }

    const headers = Object.keys(results[0]);
    const csvHeader = headers.join(',');
    const csvRows = results.map(row =>
      headers.map(header => {
        const value = row[header];
        const strValue = String(value === null || value === undefined ? '' : value);
        return `"${strValue.replace(/"/g, '""')}"`;
      }).join(',')
    );
    const csvContent = [csvHeader, ...csvRows].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="distribution_label_export.csv"');
    res.status(200).send(csvContent);
  } catch (err) {
    console.error("❌ Database query error on /api/distribution-label/export:", err);
    res.status(500).json({ error: 'CSV export failed' });
  }
});

app.put('/api/distributionlabel/:LabelID', async (req, res) => {
 const { LabelID } = req.params;
  const { LabelName, LastModifiedBy } = req.body;

  if (!LabelID) {
    return res.status(400).json({ error: "LabelID is required." });
  }
  if (!LabelName) {
    return res.status(400).json({ error: "LabelName is required." });
  }
  if (!LastModifiedBy) {
    return res.status(400).json({ error: "LastModifiedBy (user email) is required." });
  }

  try {
    const query = `
      UPDATE DistributionLabel
      SET LabelName = ?, LastModifiedBy = ?, LastModifiedTimestamp = NOW()
      WHERE LabelID = ?
    `;
    const [result] = await db.query(query, [LabelName, LastModifiedBy, LabelID]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: `Distribution Label with ID ${LabelID} not found.` });
    }
    res.status(200).json({ message: "LabelName updated successfully." });
  } catch (err) {
    console.error("❌ Database query error on /api/distribution-label/:LabelID:", err);
    res.status(500).json({ error: "Failed to update LabelName." });
  }
});


app.post('/api/distribution-label', async (req, res) => {
  const { LabelName, LastModifiedBy } = req.body;

  if (!LabelName) {
    return res.status(400).json({ error: "LabelName is required." });
  }
  if (!LastModifiedBy) {
    return res.status(400).json({ error: "LastModifiedBy (user email) is required." });
  }

  try {
    const query = `
      INSERT INTO DistributionLabel (LabelName, LastModifiedBy, LastModifiedTimestamp)
      VALUES (?, ?, NOW())
    `;
    const [result] = await db.query(query, [LabelName, LastModifiedBy]);

    res.status(201).json({
      message: "Distribution Label added successfully.",
      LabelID: result.insertId,
      LabelName,
      LastModifiedBy,
      LastModifiedTimestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error("❌ Database query error on POST /api/distribution-label:", err);
    res.status(500).json({ error: "Failed to add Distribution Label." });
  }
});
// --- NEW ENDPOINT FOR 'EdType' DROPDOWN ---
app.get('/api/editing-type/options', async (req, res) => {
  try {
    // 1. Fetch all non-empty, distinct EditingType strings from the NewMediaLog table.
    const query = `
      SELECT DISTINCT EditingType
      FROM NewMediaLog
      WHERE EditingType IS NOT NULL AND TRIM(EditingType) <> ''
    `;
    const [rows] = await db.query(query);

    // 2. Process the results to get individual unique values.
    const allTypes = new Set();
    rows.forEach(row => {
      if (row.EditingType) {
        row.EditingType.split(',')
          .map(t => t.trim())
          .filter(t => t !== '')
          .forEach(t => allTypes.add(t));
      }
    });

    // 3. Convert the Set to a sorted array of objects for the frontend.
    const uniqueTypes = Array.from(allTypes).sort();
    const results = uniqueTypes.map(t => ({ EditingType: t }));

    res.status(200).json(results);
  } catch (err) {
    console.error("❌ Database query error on /api/editing-type/options:", err);
    res.status(500).json({ error: 'Failed to fetch Editing Type options.' });
  }
});

app.get('/api/editing-type', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1; // Default to page 1
    const limit = parseInt(req.query.limit) || 50; // Default to 50 items per page
    const offset = (page - 1) * limit;

    const filterableColumns = [
      'EdID',
      'EdType',
      'AudioVideo',
    ];

    const { whereString, params } = buildWhereClause(
      req.query,
      ['EdID', 'EdType', 'AudioVideo'], // Searchable fields
      filterableColumns
    );

    const orderByString = buildOrderByClause(req.query, filterableColumns);

    // --- Count Query ---
    const countQuery = `SELECT COUNT(*) as total FROM EditingType ${whereString}`;
    const [[{ total }]] = await db.query(countQuery, params);
    const totalPages = Math.ceil(total / limit);

    // --- Data Query ---
    const dataQuery = `
      SELECT * 
      FROM EditingType 
      ${whereString} 
      ${orderByString} 
      LIMIT ? OFFSET ?
    `;
    const [results] = await db.query(dataQuery, [...params, limit, offset]);

    res.json({
      data: results,
      pagination: {
        page,
        limit,
        totalItems: total,
        totalPages,
      },
    });
  } catch (err) {
    console.error("❌ Database query error on /api/editing-type:", err);
    res.status(500).json({ error: 'Failed to fetch Editing Type data' });
  }
});

app.get('/api/editing-type/export', async (req, res) => {
  try {
    const { whereString, params } = buildWhereClause(
      req.query,
      ['EdID', 'EdType', 'AudioVideo'], // Searchable fields
      ['EdID', 'EdType', 'AudioVideo'] // Filterable columns
    );

    const dataQuery = `SELECT * FROM EditingType ${whereString}`;
    const [results] = await db.query(dataQuery, params);

    if (results.length === 0) {
      return res.status(404).send("No data found to export for the given filters.");
    }

    const headers = Object.keys(results[0]);
    const csvHeader = headers.join(',');
    const csvRows = results.map(row =>
      headers.map(header => {
        const value = row[header];
        const strValue = String(value === null || value === undefined ? '' : value);
        return `"${strValue.replace(/"/g, '""')}"`;
      }).join(',')
    );
    const csvContent = [csvHeader, ...csvRows].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="editing_type_export.csv"');
    res.status(200).send(csvContent);
  } catch (err) {
    console.error("❌ Database query error on /api/editing-type/export:", err);
    res.status(500).json({ error: 'CSV export failed' });
  }
});

app.put('/api/editingtype/:EdID', async (req, res) => {
  const { EdID } = req.params;
  const { EdType, AudioVideo, LastModifiedBy } = req.body;

  if (!EdID) {
    return res.status(400).json({ error: "EdID is required." });
  }
  if (!EdType) {
    return res.status(400).json({ error: "EdType is required." });
  }
  if (!AudioVideo) {
    return res.status(400).json({ error: "AudioVideo is required." });
  }
  if (!LastModifiedBy) {
    return res.status(400).json({ error: "LastModifiedBy (user email) is required." });
  }

  try {
    const query = `
      UPDATE EditingType
      SET EdType = ?, AudioVideo = ?, LastModifiedBy = ?, LastModifiedTimestamp = NOW()
      WHERE EdID = ?
    `;
    const [result] = await db.query(query, [EdType, AudioVideo, LastModifiedBy, EdID]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: `Editing Type with ID ${EdID} not found.` });
    }
    res.status(200).json({ message: "Editing Type updated successfully." });
  } catch (err) {
    console.error("❌ Database query error on /api/editing-type/:EdID:", err);
    res.status(500).json({ error: "Failed to update Editing Type." });
  }
});


app.post('/api/editing-type', async (req, res) => {
  const { EdType, AudioVideo, LastModifiedBy } = req.body;

  if (!EdType) {
    return res.status(400).json({ error: "EdType is required." });
  }
  if (!AudioVideo) {
    return res.status(400).json({ error: "AudioVideo is required." });
  }
  if (!LastModifiedBy) {
    return res.status(400).json({ error: "LastModifiedBy (user email) is required." });
  }

  try {
    const query = `
      INSERT INTO EditingType (EdType, AudioVideo, LastModifiedBy, LastModifiedTimestamp)
      VALUES (?, ?, ?, NOW())
    `;
    const [result] = await db.query(query, [EdType, AudioVideo, LastModifiedBy]);

    res.status(201).json({
      message: "Editing Type added successfully.",
      EdID: result.insertId,
      EdType,
      AudioVideo,
      LastModifiedBy,
      LastModifiedTimestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error("❌ Database query error on POST /api/editing-type:", err);
    res.status(500).json({ error: "Failed to add Editing Type." });
  }
});
// --- NEW ENDPOINT FOR 'EdType' DROPDOWN ---
app.get('/api/editing-status/options', async (req, res) => {
  try {
    // 1. Fetch all non-empty, distinct EditingStatus strings from the NewMediaLog table.
    const query = `
      SELECT DISTINCT EditingStatus
      FROM NewMediaLog
      WHERE EditingStatus IS NOT NULL AND TRIM(EditingStatus) <> ''
    `;
    const [rows] = await db.query(query);

    // 2. Process the results to get individual unique values.
    const allStatuses = new Set();
    rows.forEach(row => {
      if (row.EditingStatus) {
        row.EditingStatus.split(',')
          .map(s => s.trim())
          .filter(s => s !== '')
          .forEach(s => allStatuses.add(s));
      }
    });

    // 3. Convert the Set to a sorted array of objects for the frontend.
    const uniqueStatuses = Array.from(allStatuses).sort();
    const results = uniqueStatuses.map(s => ({ EditingStatus: s }));

    res.status(200).json(results);
  } catch (err) {
    console.error("❌ Database query error on /api/editing-status/options:", err);
    res.status(500).json({ error: 'Failed to fetch Editing Status options.' });
  }
});

app.get('/api/editing-status', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1; // Default to page 1
    const limit = parseInt(req.query.limit) || 50; // Default to 50 items per page
    const offset = (page - 1) * limit;

    const filterableColumns = [
      'EdID',
      'EdType',
      'AudioVideo',
    ];

    const { whereString, params } = buildWhereClause(
      req.query,
      ['EdID', 'EdType', 'AudioVideo'], // Searchable fields
      filterableColumns
    );

    const orderByString = buildOrderByClause(req.query, filterableColumns);

    // --- Count Query ---
    const countQuery = `SELECT COUNT(*) as total FROM EditingType ${whereString}`;
    const [[{ total }]] = await db.query(countQuery, params);
    const totalPages = Math.ceil(total / limit);

    // --- Data Query ---
    const dataQuery = `
      SELECT * 
      FROM EditingType 
      ${whereString} 
      ${orderByString} 
      LIMIT ? OFFSET ?
    `;
    const [results] = await db.query(dataQuery, [...params, limit, offset]);

    res.json({
      data: results,
      pagination: {
        page,
        limit,
        totalItems: total,
        totalPages,
      },
    });
  } catch (err) {
    console.error("❌ Database query error on /api/editing-status:", err);
    res.status(500).json({ error: 'Failed to fetch Editing Status data' });
  }
});

app.get('/api/editing-status/export', async (req, res) => {
  try {
    const { whereString, params } = buildWhereClause(
      req.query,
      ['EdID', 'EdType', 'AudioVideo'], // Searchable fields
      ['EdID', 'EdType', 'AudioVideo'] // Filterable columns
    );
    const dataQuery = `SELECT * FROM EditingType ${whereString}`;
    const [results] = await db.query(dataQuery, params);
    if (results.length === 0) {
      return res.status(404).send("No data found to export for the given filters.");
    }
    const headers = Object.keys(results[0]);
    const csvHeader = headers.join(',');
    const csvRows = results.map(row =>
      headers.map(header => {
        const value = row[header];
        const strValue = String(value === null || value === undefined ? '' : value);
        return `"${strValue.replace(/"/g, '""')}"`;
      }).join(',')
    );
    const csvContent = [csvHeader, ...csvRows].join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="editing_status_export.csv"');
    res.status(200).send(csvContent);
  }
  catch (err) {
    console.error("❌ Database query error on /api/editing-status/export:", err);
    res.status(500).json({ error: 'CSV export failed' });
  }
});

app.put('/api/editingstatus/:EdID', async (req, res) => {
  const { EdID } = req.params;
  const { EdType, AudioVideo, LastModifiedBy } = req.body;

  if (!EdID) return res.status(400).json({ error: "EdID is required." });
  if (!EdType) return res.status(400).json({ error: "EdType is required." });
  if (!AudioVideo) return res.status(400).json({ error: "AudioVideo is required." });
  if (!LastModifiedBy) return res.status(400).json({ error: "LastModifiedBy (user email) is required." });

  try {
    const query = `
      UPDATE EditingType
      SET EdType = ?, AudioVideo = ?, LastModifiedBy = ?, LastModifiedTimestamp = NOW()
      WHERE EdID = ?
    `;
    const [result] = await db.query(query, [EdType, AudioVideo, LastModifiedBy, EdID]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: `Editing Status with ID ${EdID} not found.` });
    }
    res.status(200).json({ message: "Editing Status updated successfully." });
  } catch (err) {
    console.error("❌ Database query error on /api/editing-status/:EdID:", err);
    res.status(500).json({ error: "Failed to update Editing Status." });
  }
});

app.post('/api/editing-status', async (req, res) => {
  const { EdType, AudioVideo, LastModifiedBy } = req.body;

  if (!EdType) {
    return res.status(400).json({ error: "EdType is required." });
  }
  if (!AudioVideo) {
    return res.status(400).json({ error: "AudioVideo is required." });
  }
  if (!LastModifiedBy) {
    return res.status(400).json({ error: "LastModifiedBy (user email) is required." });
  }

  try {
    const query = `
      INSERT INTO EditingType (EdType, AudioVideo, LastModifiedBy, LastModifiedTimestamp)
      VALUES (?, ?, ?, NOW())
    `;
    const [result] = await db.query(query, [EdType, AudioVideo, LastModifiedBy]);

    res.status(201).json({
      message: "Editing Status added successfully.",
      EdID: result.insertId,
      EdType,
      AudioVideo,
      LastModifiedBy,
      LastModifiedTimestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error("❌ Database query error on POST /api/editing-status:", err);
    res.status(500).json({ error: "Failed to add Editing Status." });
  }
});
// --- NEW ENDPOINT FOR 'Category' (EventCategory) DROPDOWN ---
app.get('/api/event-category/options', async (req, res) => {
  try {
    // 1. Fetch all non-empty, distinct fkEventCategory strings from the Events table.
    const query = `
      SELECT DISTINCT fkEventCategory
      FROM Events
      WHERE fkEventCategory IS NOT NULL AND TRIM(fkEventCategory) <> ''
    `;
    const [rows] = await db.query(query);

    // 2. Process the results to get individual unique values.
    const allCategories = new Set();
    rows.forEach(row => {
      if (row.fkEventCategory) {
        row.fkEventCategory.split(',')
          .map(c => c.trim())
          .filter(c => c !== '')
          .forEach(c => allCategories.add(c));
      }
    });

    // 3. Convert the Set to a sorted array of objects for the frontend.
    const uniqueCategories = Array.from(allCategories).sort();
    const results = uniqueCategories.map(c => ({ fkEventCategory: c }));

    res.status(200).json(results);
  } catch (err) {
    console.error("❌ Database query error on /api/event-category/options:", err);
    res.status(500).json({ error: 'Failed to fetch event category options.' });
  }
});

app.get('/api/event-category', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1; // Default to page 1
    const limit = parseInt(req.query.limit) || 50; // Default to 50 items per page
    const offset = (page - 1) * limit;

    const filterableColumns = [
      'EventCategoryID',
      'EventCategory',
      'LastModifiedTimestamp',
    ];

    const { whereString, params } = buildWhereClause(
      req.query,
      ['EventCategoryID', 'EventCategory'], // Searchable fields
      filterableColumns
    );

    const orderByString = buildOrderByClause(req.query, filterableColumns);

    // --- Count Query ---
    const countQuery = `SELECT COUNT(*) as total FROM EventCategory ${whereString}`;
    const [[{ total }]] = await db.query(countQuery, params);
    const totalPages = Math.ceil(total / limit);

    // --- Data Query ---
    const dataQuery = `
      SELECT * 
      FROM EventCategory 
      ${whereString} 
      ${orderByString} 
      LIMIT ? OFFSET ?
    `;
    const [results] = await db.query(dataQuery, [...params, limit, offset]);

    res.json({
      data: results,
      pagination: {
        page,
        limit,
        totalItems: total,
        totalPages,
      },
    });
  } catch (err) {
    console.error("❌ Database query error on /api/event-category:", err);
    res.status(500).json({ error: 'Failed to fetch Event Category data' });
  }
});


app.get('/api/event-category/export', async (req, res) => {
  try {
    const { whereString, params } = buildWhereClause(
      req.query,
      ['EventCategoryID', 'EventCategory'], // Searchable fields
      ['EventCategoryID', 'EventCategory', 'LastModifiedTimestamp'] // Filterable columns
    );

    const dataQuery = `SELECT * FROM EventCategory ${whereString}`;
    const [results] = await db.query(dataQuery, params);

    if (results.length === 0) {
      return res.status(404).send("No data found to export for the given filters.");
    }

    const headers = Object.keys(results[0]);
    const csvHeader = headers.join(',');
    const csvRows = results.map(row =>
      headers.map(header => {
        const value = row[header];
        const strValue = String(value === null || value === undefined ? '' : value);
        return `"${strValue.replace(/"/g, '""')}"`;
      }).join(',')
    );
    const csvContent = [csvHeader, ...csvRows].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="event_category_export.csv"');
    res.status(200).send(csvContent);
  } catch (err) {
    console.error("❌ Database query error on /api/event-category/export:", err);
    res.status(500).json({ error: 'CSV export failed' });
  }
});

app.put('/api/eventcategory/:EventCategoryID', async (req, res) => {
    const { EventCategoryID } = req.params;
  const { EventCategory, LastModifiedBy } = req.body;

  if (!EventCategoryID) return res.status(400).json({ error: "EventCategoryID is required." });
  if (!EventCategory) return res.status(400).json({ error: "EventCategory is required." });
  if (!LastModifiedBy) return res.status(400).json({ error: "LastModifiedBy (user email) is required." });

  try {
    const query = `
      UPDATE EventCategory
      SET EventCategory = ?, LastModifiedBy = ?, LastModifiedTimestamp = NOW()
      WHERE EventCategoryID = ?
    `;
    const [result] = await db.query(query, [EventCategory, LastModifiedBy, EventCategoryID]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: `Event Category with ID ${EventCategoryID} not found.` });
    }
    res.status(200).json({ message: "Event Category updated successfully." });
  } catch (err) {
    console.error("❌ Database query error on /api/event-category/:EventCategoryID:", err);
    res.status(500).json({ error: "Failed to update Event Category." });
  }
});

app.post('/api/event-category', async (req, res) => {
  const { EventCategory, LastModifiedBy } = req.body;

  if (!EventCategory) {
    return res.status(400).json({ error: "EventCategory is required." });
  }
  if (!LastModifiedBy) {
    return res.status(400).json({ error: "LastModifiedBy (user email) is required." });
  }

  try {
    const query = `
      INSERT INTO EventCategory (EventCategory, LastModifiedBy, LastModifiedTimestamp)
      VALUES (?, ?, NOW())
    `;
    const [result] = await db.query(query, [EventCategory, LastModifiedBy]);

    res.status(201).json({
      message: "Event Category added successfully.",
      EventCategoryID: result.insertId,
      EventCategory,
      LastModifiedBy,
      LastModifiedTimestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error("❌ Database query error on POST /api/event-category:", err);
    res.status(500).json({ error: "Failed to add Event Category." });
  }
});
// --- NEW ENDPOINT FOR 'FootageType' DROPDOWN ---
app.get('/api/footage-type/options', async (req, res) => {
  try {
    // 1. Fetch all non-empty, distinct FootageType strings from the NewMediaLog table.
    const query = `
      SELECT DISTINCT FootageType
      FROM NewMediaLog
      WHERE FootageType IS NOT NULL AND TRIM(FootageType) <> ''
    `;
    const [rows] = await db.query(query);

    // 2. Process the results to get individual unique values.
    const allTypes = new Set();
    rows.forEach(row => {
      if (row.FootageType) {
        row.FootageType.split(',')
          .map(t => t.trim())
          .filter(t => t !== '')
          .forEach(t => allTypes.add(t));
      }
    });

    // 3. Convert the Set to a sorted array of objects for the frontend.
    const uniqueTypes = Array.from(allTypes).sort();
    const results = uniqueTypes.map(t => ({ FootageType: t }));

    res.status(200).json(results);
  } catch (err) {
    console.error("❌ Database query error on /api/footage-type/options:", err);
    res.status(500).json({ error: 'Failed to fetch footage type options.' });
  }
});

app.get('/api/footage-type', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1; // Default to page 1
    const limit = parseInt(req.query.limit) || 50; // Default to 50 items per page
    const offset = (page - 1) * limit;

    const filterableColumns = [
      'FootageID',
      'FootageTypeList',
      'LastModifiedTimestamp',
    ];

    const { whereString, params } = buildWhereClause(
      req.query,
      ['FootageID', 'FootageTypeList'], // Searchable fields
      filterableColumns
    );

    const orderByString = buildOrderByClause(req.query, filterableColumns);

    // --- Count Query ---
    const countQuery = `SELECT COUNT(*) as total FROM FootageTypes ${whereString}`;
    const [[{ total }]] = await db.query(countQuery, params);
    const totalPages = Math.ceil(total / limit);

    // --- Data Query ---
    const dataQuery = `
      SELECT * 
      FROM FootageTypes 
      ${whereString} 
      ${orderByString} 
      LIMIT ? OFFSET ?
    `;
    const [results] = await db.query(dataQuery, [...params, limit, offset]);

    res.json({
      data: results,
      pagination: {
        page,
        limit,
        totalItems: total,
        totalPages,
      },
    });
  } catch (err) {
    console.error("❌ Database query error on /api/footage-type:", err);
    res.status(500).json({ error: 'Failed to fetch Footage Type data' });
  }
});

app.get('/api/footage-type/export', async (req, res) => {
  try {
    const { whereString, params } = buildWhereClause(
      req.query,
      ['FootageID', 'FootageTypeList'], // Searchable fields
      ['FootageID', 'FootageTypeList', 'LastModifiedTimestamp'] // Filterable columns
    );

    const dataQuery = `SELECT * FROM FootageTypes ${whereString}`;
    const [results] = await db.query(dataQuery, params);

    if (results.length === 0) {
      return res.status(404).send("No data found to export for the given filters.");
    }

    const headers = Object.keys(results[0]);
    const csvHeader = headers.join(',');
    const csvRows = results.map(row =>
      headers.map(header => {
        const value = row[header];
        const strValue = String(value === null || value === undefined ? '' : value);
        return `"${strValue.replace(/"/g, '""')}"`;
      }).join(',')
    );
    const csvContent = [csvHeader, ...csvRows].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="footage_type_export.csv"');
    res.status(200).send(csvContent);
  } catch (err) {
    console.error("❌ Database query error on /api/footage-type/export:", err);
    res.status(500).json({ error: 'CSV export failed' });
  }
});


// --- NEW ENDPOINT FOR 'FormateType' DROPDOWN ---
app.get('/api/format-type/options', async (req, res) => {
  try {
    // 1. Fetch all non-empty, distinct fkMediaName strings from the DigitalRecordings table.
    const query = `
      SELECT DISTINCT fkMediaName
      FROM DigitalRecordings
      WHERE fkMediaName IS NOT NULL AND TRIM(fkMediaName) <> ''
    `;
    const [rows] = await db.query(query);

    // 2. Process the results to get individual unique values.
    const allTypes = new Set();
    rows.forEach(row => {
      if (row.fkMediaName) {
        row.fkMediaName.split(',')
          .map(t => t.trim())
          .filter(t => t !== '')
          .forEach(t => allTypes.add(t));
      }
    });

    // 3. Convert the Set to a sorted array of objects for the frontend.
    const uniqueTypes = Array.from(allTypes).sort();
    const results = uniqueTypes.map(t => ({ fkMediaName: t }));

    res.status(200).json(results);
  } catch (err) {
    console.error("❌ Database query error on /api/format-type/options:", err);
    res.status(500).json({ error: 'Failed to fetch format type options.' });
  }
});

app.put('/api/footagetype/:FootageID', async (req, res) => {
  const { FootageID } = req.params;
  const { FootageTypeList, LastModifiedBy } = req.body;

  if (!FootageID) return res.status(400).json({ error: "FootageID is required." });
  if (!FootageTypeList) return res.status(400).json({ error: "FootageTypeList is required." });
  if (!LastModifiedBy) return res.status(400).json({ error: "LastModifiedBy (user email) is required." });

  try {
    const query = `
      UPDATE FootageTypes
      SET FootageTypeList = ?, LastModifiedBy = ?, LastModifiedTimestamp = NOW()
      WHERE FootageID = ?
    `;
    const [result] = await db.query(query, [FootageTypeList, LastModifiedBy, FootageID]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: `Footage Type with ID ${FootageID} not found.` });
    }
    res.status(200).json({ message: "Footage Type updated successfully." });
  } catch (err) {
    console.error("❌ Database query error on /api/footage-type/:FootageID:", err);
    res.status(500).json({ error: "Failed to update Footage Type." });
  }
});

app.post('/api/footage-type', async (req, res) => {
  const { FootageTypeList, LastModifiedBy } = req.body;

  if (!FootageTypeList) {
    return res.status(400).json({ error: "FootageTypeList is required." });
  }
  if (!LastModifiedBy) {
    return res.status(400).json({ error: "LastModifiedBy (user email) is required." });
  }

  try {
    const query = `
      INSERT INTO FootageTypes (FootageTypeList, LastModifiedBy, LastModifiedTimestamp)
      VALUES (?, ?, NOW())
    `;
    const [result] = await db.query(query, [FootageTypeList, LastModifiedBy]);

    res.status(201).json({
      message: "Footage Type added successfully.",
      FootageID: result.insertId,
      FootageTypeList,
      LastModifiedBy,
      LastModifiedTimestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error("❌ Database query error on POST /api/footage-type:", err);
    res.status(500).json({ error: "Failed to add Footage Type." });
  }
});

app.get('/api/format-type', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1; // Default to page 1
    const limit = parseInt(req.query.limit) || 50; // Default to 50 items per page
    const offset = (page - 1) * limit;

    const filterableColumns = [
      'FTID',
      'Type',
      'LastModifiedTimestamp',
    ];

    const { whereString, params } = buildWhereClause(
      req.query,
      ['FTID', 'Type'], // Searchable fields
      filterableColumns
    );

    const orderByString = buildOrderByClause(req.query, filterableColumns);

    // --- Count Query ---
    const countQuery = `SELECT COUNT(*) as total FROM Format ${whereString}`;
    const [[{ total }]] = await db.query(countQuery, params);
    const totalPages = Math.ceil(total / limit);

    // --- Data Query ---
    const dataQuery = `
      SELECT * 
      FROM Format 
      ${whereString} 
      ${orderByString} 
      LIMIT ? OFFSET ?
    `;
    const [results] = await db.query(dataQuery, [...params, limit, offset]);

    res.json({
      data: results,
      pagination: {
        page,
        limit,
        totalItems: total,
        totalPages,
      },
    });
  } catch (err) {
    console.error("❌ Database query error on /api/format-type:", err);
    res.status(500).json({ error: 'Failed to fetch Format Type data' });
  }
});

app.get('/api/format-type/export', async (req, res) => {
  try {
    const { whereString, params } = buildWhereClause(
      req.query,
      ['FTID', 'Type'], // Searchable fields
      ['FTID', 'Type', 'LastModifiedTimestamp'] // Filterable columns
    );

    const dataQuery = `SELECT * FROM Format ${whereString}`;
    const [results] = await db.query(dataQuery, params);

    if (results.length === 0) {
      return res.status(404).send("No data found to export for the given filters.");
    }

    const headers = Object.keys(results[0]);
    const csvHeader = headers.join(',');
    const csvRows = results.map(row =>
      headers.map(header => {
        const value = row[header];
        const strValue = String(value === null || value === undefined ? '' : value);
        return `"${strValue.replace(/"/g, '""')}"`;
      }).join(',')
    );
    const csvContent = [csvHeader, ...csvRows].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="format_type_export.csv"');
    res.status(200).send(csvContent);
  } catch (err) {
    console.error("❌ Database query error on /api/format-type/export:", err);
    res.status(500).json({ error: 'CSV export failed' });
  }
});

app.put('/api/formattype/:FTID', async (req, res) => {
    const { FTID } = req.params;
  const { Type, LastModifiedBy } = req.body;

  if (!FTID) {
    return res.status(400).json({ error: "Format Type ID (FTID) is required." });
  }
  if (!Type) {
    return res.status(400).json({ error: "Type is required." });
  }
  if (!LastModifiedBy) {
    return res.status(400).json({ error: "LastModifiedBy (user email) is required." });
  }

  try {
    const query = `
      UPDATE Format
      SET Type = ?, LastModifiedBy = ?, LastModifiedTimestamp = NOW()
      WHERE FTID = ?
    `;
    const [result] = await db.query(query, [Type, LastModifiedBy, FTID]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: `Format Type with ID ${FTID} not found.` });
    }
    res.status(200).json({ message: "Type updated successfully." });
  } catch (err) {
    console.error("❌ Database query error on /api/formattype/:FTID:", err);
    res.status(500).json({ error: "Failed to update Type." });
  }
});


app.post('/api/format-type', async (req, res) => {
  const { Type, LastModifiedBy } = req.body;

  if (!Type) {
    return res.status(400).json({ error: "Type is required." });
  }
  if (!LastModifiedBy) {
    return res.status(400).json({ error: "LastModifiedBy (user email) is required." });
  }

  try {
    const query = `
      INSERT INTO Format (Type, LastModifiedBy, LastModifiedTimestamp)
      VALUES (?, ?, NOW())
    `;
    const [result] = await db.query(query, [Type, LastModifiedBy]);

    res.status(201).json({
      message: "Format Type added successfully.",
      FTID: result.insertId,
      Type,
      LastModifiedBy,
      LastModifiedTimestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error("❌ Database query error on POST /api/format-type:", err);
    res.status(500).json({ error: "Failed to add Format Type." });
  }
});
// --- NEW ENDPOINT FOR 'fkGranth' DROPDOWN ---
app.get('/api/granths/options', async (req, res) => {
  try {
    // 1. Fetch all non-empty, distinct fkGranth strings from the NewMediaLog table.
    const query = `
      SELECT DISTINCT fkGranth
      FROM NewMediaLog
      WHERE fkGranth IS NOT NULL AND TRIM(fkGranth) <> ''
    `;
    const [rows] = await db.query(query);

    // 2. Process the results to get individual unique values.
    const allGranths = new Set();
    rows.forEach(row => {
      if (row.fkGranth) {
        row.fkGranth.split(',')
          .map(g => g.trim())
          .filter(g => g !== '')
          .forEach(g => allGranths.add(g));
      }
    });

    // 3. Convert the Set to a sorted array of objects for the frontend.
    const uniqueGranths = Array.from(allGranths).sort();
    const results = uniqueGranths.map(g => ({ fkGranth: g }));

    res.status(200).json(results);
  } catch (err) {
    console.error("❌ Database query error on /api/granths/options:", err);
    res.status(500).json({ error: 'Failed to fetch granth options.' });
  }
});

app.get('/api/granths', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1; // Default to page 1
    const limit = parseInt(req.query.limit) || 50; // Default to 50 items per page
    const offset = (page - 1) * limit;

    const filterableColumns = [
      'ID',
      'Name',
    ];

    const { whereString, params } = buildWhereClause(
      req.query,
      ['ID', 'Name'], // Searchable fields
      filterableColumns
    );

    const orderByString = buildOrderByClause(req.query, filterableColumns);

    // --- Count Query ---
    const countQuery = `SELECT COUNT(*) as total FROM NewGranths ${whereString}`;
    const [[{ total }]] = await db.query(countQuery, params);
    const totalPages = Math.ceil(total / limit);

    // --- Data Query ---
    const dataQuery = `
      SELECT * 
      FROM NewGranths 
      ${whereString} 
      ${orderByString} 
      LIMIT ? OFFSET ?
    `;
    const [results] = await db.query(dataQuery, [...params, limit, offset]);

    res.json({
      data: results,
      pagination: {
        page,
        limit,
        totalItems: total,
        totalPages,
      },
    });
  } catch (err) {
    console.error("❌ Database query error on /api/granths:", err);
    res.status(500).json({ error: 'Failed to fetch Granths data' });
  }
});

app.get('/api/granths/export', async (req, res) => {
  try {
    const { whereString, params } = buildWhereClause(
      req.query,
      ['ID', 'Name'], // Searchable fields
      ['ID', 'Name'] // Filterable columns
    );

    const dataQuery = `SELECT * FROM NewGranths ${whereString}`;
    const [results] = await db.query(dataQuery, params);

    if (results.length === 0) {
      return res.status(404).send("No data found to export for the given filters.");
    }

    const headers = Object.keys(results[0]);
    const csvHeader = headers.join(',');
    const csvRows = results.map(row =>
      headers.map(header => {
        const value = row[header];
        const strValue = String(value === null || value === undefined ? '' : value);
        return `"${strValue.replace(/"/g, '""')}"`;
      }).join(',')
    );
    const csvContent = [csvHeader, ...csvRows].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="granths_export.csv"');
    res.status(200).send(csvContent);
  } catch (err) {
    console.error("❌ Database query error on /api/granths/export:", err);
    res.status(500).json({ error: 'CSV export failed' });
  }
});

app.put('/api/granths/:ID', async (req, res) => {
  const { ID } = req.params;
  const { Name, LastModifiedBy } = req.body;

  if (!ID) {
    return res.status(400).json({ error: "Granth ID (ID) is required." });
  }
  if (!Name) {
    return res.status(400).json({ error: "Name is required." });
  }
  if (!LastModifiedBy) {
    return res.status(400).json({ error: "LastModifiedBy (user email) is required." });
  }

  try {
    const query = `
      UPDATE NewGranths
      SET Name = ?, LastModifiedBy = ?, LastModifiedTimestamp = NOW()
      WHERE ID = ?
    `;
    const [result] = await db.query(query, [Name, LastModifiedBy, ID]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: `Granth with ID ${ID} not found.` });
    }
    res.status(200).json({ message: "Name updated successfully." });
  } catch (err) {
    console.error("❌ Database query error on /api/granths/:ID:", err);
    res.status(500).json({ error: "Failed to update Name." });
  }
});

app.post('/api/granths', async (req, res) => {
  const { Name, LastModifiedBy } = req.body;

  if (!Name) {
    return res.status(400).json({ error: "Name is required." });
  }
  if (!LastModifiedBy) {
    return res.status(400).json({ error: "LastModifiedBy (user email) is required." });
  }

  try {
    const query = `
      INSERT INTO NewGranths (Name, LastModifiedBy, LastModifiedTimestamp)
      VALUES (?, ?, NOW())
    `;
    const [result] = await db.query(query, [Name, LastModifiedBy]);

    res.status(201).json({
      message: "Granth added successfully.",
      ID: result.insertId,
      Name,
      LastModifiedBy,
      LastModifiedTimestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error("❌ Database query error on POST /api/granths:", err);
    res.status(500).json({ error: "Failed to add Granth." });
  }
});
// --- NEW ENDPOINT FOR 'Language' DROPDOWN ---
app.get('/api/language/options', async (req, res) => {
  try {
    // 1. Fetch all non-empty, distinct Language strings from the NewMediaLog table.
    const query = `
      SELECT DISTINCT Language
      FROM NewMediaLog
      WHERE Language IS NOT NULL AND TRIM(Language) <> ''
    `;
    const [rows] = await db.query(query);

    // 2. Process the results to get individual unique values.
    const allLanguages = new Set();
    rows.forEach(row => {
      if (row.Language) {
        row.Language.split(',')
          .map(l => l.trim())
          .filter(l => l !== '')
          .forEach(l => allLanguages.add(l));
      }
    });

    // 3. Convert the Set to a sorted array of objects for the frontend.
    const uniqueLanguages = Array.from(allLanguages).sort();
    const results = uniqueLanguages.map(l => ({ Language: l }));

    res.status(200).json(results);
  } catch (err) {
    console.error("❌ Database query error on /api/language/options:", err);
    res.status(500).json({ error: 'Failed to fetch language options.' });
  }
});

app.get('/api/language', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1; // Default to page 1
    const limit = parseInt(req.query.limit) || 50; // Default to 50 items per page
    const offset = (page - 1) * limit;

    const filterableColumns = [
      'STID',
      'TitleLanguage',
      'LastModifiedTimestamp',
    ];

    const { whereString, params } = buildWhereClause(
      req.query,
      ['STID', 'TitleLanguage'], // Searchable fields
      filterableColumns
    );

    const orderByString = buildOrderByClause(req.query, filterableColumns);

    // --- Count Query ---
    const countQuery = `SELECT COUNT(*) as total FROM SubTitlesLanguages ${whereString}`;
    const [[{ total }]] = await db.query(countQuery, params);
    const totalPages = Math.ceil(total / limit);

    // --- Data Query ---
    const dataQuery = `
      SELECT * 
      FROM SubTitlesLanguages 
      ${whereString} 
      ${orderByString} 
      LIMIT ? OFFSET ?
    `;
    const [results] = await db.query(dataQuery, [...params, limit, offset]);

    res.json({
      data: results,
      pagination: {
        page,
        limit,
        totalItems: total,
        totalPages,
      },
    });
  } catch (err) {
    console.error("❌ Database query error on /api/language:", err);
    res.status(500).json({ error: 'Failed to fetch Language data' });
  }
});

app.get('/api/language/export', async (req, res) => {
  try {
    const { whereString, params } = buildWhereClause(
      req.query,
      ['STID', 'TitleLanguage'], // Searchable fields
      ['STID', 'TitleLanguage', 'LastModifiedTimestamp'] // Filterable columns
    );

    const dataQuery = `SELECT * FROM SubTitlesLanguages ${whereString}`;
    const [results] = await db.query(dataQuery, params);

    if (results.length === 0) {
      return res.status(404).send("No data found to export for the given filters.");
    }

    const headers = Object.keys(results[0]);
    const csvHeader = headers.join(',');
    const csvRows = results.map(row =>
      headers.map(header => {
        const value = row[header];
        const strValue = String(value === null || value === undefined ? '' : value);
        return `"${strValue.replace(/"/g, '""')}"`;
      }).join(',')
    );
    const csvContent = [csvHeader, ...csvRows].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="language_export.csv"');
    res.status(200).send(csvContent);
  } catch (err) {
    console.error("❌ Database query error on /api/language/export:", err);
    res.status(500).json({ error: 'CSV export failed' });
  }
});

app.put('/api/language/:STID', async (req, res) => {
  const { STID } = req.params;
  const { TitleLanguage, LastModifiedBy } = req.body;

  if (!STID) return res.status(400).json({ error: "STID is required." });
  if (!TitleLanguage) return res.status(400).json({ error: "TitleLanguage is required." });
  if (!LastModifiedBy) return res.status(400).json({ error: "LastModifiedBy (user email) is required." });

  try {
    const query = `
      UPDATE SubTitlesLanguages
      SET TitleLanguage = ?, LastModifiedBy = ?, LastModifiedTimestamp = NOW()
      WHERE STID = ?
    `;
    const [result] = await db.query(query, [TitleLanguage, LastModifiedBy, STID]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: `Language with ID ${STID} not found.` });
    }
    res.status(200).json({ message: "TitleLanguage updated successfully." });
  } catch (err) {
    console.error("❌ Database query error on /api/language/:STID:", err);
    res.status(500).json({ error: "Failed to update TitleLanguage." });
  }
});

app.post('/api/language', async (req, res) => {
  const { TitleLanguage, LastModifiedBy } = req.body;

  if (!TitleLanguage) {
    return res.status(400).json({ error: "TitleLanguage is required." });
  }
  if (!LastModifiedBy) {
    return res.status(400).json({ error: "LastModifiedBy (user email) is required." });
  }

  try {
    const query = `
      INSERT INTO SubTitlesLanguages (TitleLanguage, LastModifiedBy, LastModifiedTimestamp)
      VALUES (?, ?, NOW())
    `;
    const [result] = await db.query(query, [TitleLanguage, LastModifiedBy]);

    res.status(201).json({
      message: "Language added successfully.",
      STID: result.insertId,
      TitleLanguage,
      LastModifiedBy,
      LastModifiedTimestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error("❌ Database query error on POST /api/language:", err);
    res.status(500).json({ error: "Failed to add Language." });
  }
});
// --- NEW ENDPOINT FOR 'MQName' DROPDOWN ---
app.get('/api/master-quality/options', async (req, res) => {
  try {
    // 1. Fetch all non-empty, distinct Masterquality strings from the DigitalRecordings table.
    const query = `
      SELECT DISTINCT Masterquality
      FROM DigitalRecordings
      WHERE Masterquality IS NOT NULL AND TRIM(Masterquality) <> ''
    `;
    const [rows] = await db.query(query);

    // 2. Process the results to get individual unique values.
    const allQualities = new Set();
    rows.forEach(row => {
      if (row.Masterquality) {
        row.Masterquality.split(',')
          .map(q => q.trim())
          .filter(q => q !== '')
          .forEach(q => allQualities.add(q));
      }
    });

    // 3. Convert the Set to a sorted array of objects for the frontend.
    const uniqueQualities = Array.from(allQualities).sort();
    const results = uniqueQualities.map(q => ({ Masterquality: q }));

    res.status(200).json(results);
  } catch (err) {
    console.error("❌ Database query error on /api/master-quality/options:", err);
    res.status(500).json({ error: 'Failed to fetch Master Quality options.' });
  }
});

app.get('/api/master-quality', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;

    const filterableColumns = [
      'MQID',
      'MQName',
      'LastModifiedTimestamp',
    ];

    const { whereString, params } = buildWhereClause(
      req.query,
      ['MQID', 'MQName'], // Searchable fields
      filterableColumns
    );

    const orderByString = buildOrderByClause(req.query, filterableColumns);

    // --- Count Query ---
    const countQuery = `SELECT COUNT(*) as total FROM MasterQuality ${whereString}`;
    const [[{ total }]] = await db.query(countQuery, params);
    const totalPages = Math.ceil(total / limit);

    // --- Data Query ---
    const dataQuery = `
      SELECT * 
      FROM MasterQuality 
      ${whereString} 
      ${orderByString} 
      LIMIT ? OFFSET ?
    `;
    const [results] = await db.query(dataQuery, [...params, limit, offset]);

    res.json({
      data: results,
      pagination: {
        page,
        limit,
        totalItems: total,
        totalPages,
      },
    });
  } catch (err) {
    console.error("❌ Database query error on /api/master-quality:", err);
    res.status(500).json({ error: 'Failed to fetch Master Quality data' });
  }
});


app.get('/api/master-quality/export', async (req, res) => {
  try {
    const { whereString, params } = buildWhereClause(
      req.query,
      ['MQID', 'MQName'], // Searchable fields
      ['MQID', 'MQName', 'LastModifiedTimestamp'] // Filterable columns
    );

    const dataQuery = `SELECT * FROM MasterQuality ${whereString}`;
    const [results] = await db.query(dataQuery, params);

    if (results.length === 0) {
      return res.status(404).send("No data found to export for the given filters.");
    }

    const headers = Object.keys(results[0]);
    const csvHeader = headers.join(',');
    const csvRows = results.map(row =>
      headers.map(header => {
        const value = row[header];
        const strValue = String(value === null || value === undefined ? '' : value);
        return `"${strValue.replace(/"/g, '""')}"`;
      }).join(',')
    );
    const csvContent = [csvHeader, ...csvRows].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="master_quality_export.csv"');
    res.status(200).send(csvContent);
  } catch (err) {
    console.error("❌ Database query error on /api/master-quality/export:", err);
    res.status(500).json({ error: 'CSV export failed' });
  }
});


app.put('/api/master-quality/:MQID', async (req, res) => {
  const { MQID } = req.params;
  const { MQName, LastModifiedBy } = req.body;

  if (!MQID) return res.status(400).json({ error: "MQID is required." });
  if (!MQName) return res.status(400).json({ error: "MQName is required." });
  if (!LastModifiedBy) return res.status(400).json({ error: "LastModifiedBy (user email) is required." });

  try {
    const query = `
      UPDATE MasterQuality
      SET MQName = ?, LastModifiedBy = ?, LastModifiedTimestamp = NOW()
      WHERE MQID = ?
    `;
    const [result] = await db.query(query, [MQName, LastModifiedBy, MQID]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: `Master Quality with ID ${MQID} not found.` });
    }
    res.status(200).json({ message: "MQName updated successfully." });
  } catch (err) {
    console.error("❌ Database query error on /api/master-quality/:MQID:", err);
    res.status(500).json({ error: "Failed to update MQName." });
  }
});

app.post('/api/master-quality', async (req, res) => {
  const { MQName, LastModifiedBy } = req.body;

  if (!MQName) {
    return res.status(400).json({ error: "MQName is required." });
  }
  if (!LastModifiedBy) {
    return res.status(400).json({ error: "LastModifiedBy (user email) is required." });
  }

  try {
    const query = `
      INSERT INTO MasterQuality (MQName, LastModifiedBy, LastModifiedTimestamp)
      VALUES (?, ?, NOW())
    `;
    const [result] = await db.query(query, [MQName, LastModifiedBy]);

    res.status(201).json({
      message: "Master Quality added successfully.",
      MQID: result.insertId,
      MQName,
      LastModifiedBy,
      LastModifiedTimestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error("❌ Database query error on POST /api/master-quality:", err);
    res.status(500).json({ error: "Failed to add Master Quality." });
  }
});

// --- NEW ENDPOINT FOR 'Organization' DROPDOWN ---
app.get('/api/organizations/options', async (req, res) => {
  try {
    // 1. Fetch all non-empty, distinct fkOrganization strings from the NewMediaLog table.
    const query = `
      SELECT DISTINCT fkOrganization
      FROM NewMediaLog
      WHERE fkOrganization IS NOT NULL AND TRIM(fkOrganization) <> ''
    `;
    const [rows] = await db.query(query);

    // 2. Process the results to get individual unique values.
    const allOrganizations = new Set();
    rows.forEach(row => {
      if (row.fkOrganization) {
        row.fkOrganization.split(',')
          .map(org => org.trim())
          .filter(org => org !== '')
          .forEach(org => allOrganizations.add(org));
      }
    });

    // 3. Convert the Set to a sorted array of objects for the frontend.
    const uniqueOrganizations = Array.from(allOrganizations).sort();
    const results = uniqueOrganizations.map(org => ({ fkOrganization: org }));

    res.status(200).json(results);
  } catch (err) {
    console.error("❌ Database query error on /api/organizations/options:", err);
    res.status(500).json({ error: 'Failed to fetch Organization options.' });
  }
});

app.get('/api/organizations', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;

    const filterableColumns = [
      'OrganizationID',
      'Organization',
      'LastModifiedTimestamp',
    ];

    const { whereString, params } = buildWhereClause(
      req.query,
      ['OrganizationID', 'Organization'], // Searchable fields
      filterableColumns
    );

    const orderByString = buildOrderByClause(req.query, filterableColumns);

    // --- Count Query ---
    const countQuery = `SELECT COUNT(*) as total FROM Organizations ${whereString}`;
    const [[{ total }]] = await db.query(countQuery, params);
    const totalPages = Math.ceil(total / limit);

    // --- Data Query ---
    const dataQuery = `
      SELECT * 
      FROM Organizations 
      ${whereString} 
      ${orderByString} 
      LIMIT ? OFFSET ?
    `;
    const [results] = await db.query(dataQuery, [...params, limit, offset]);

    res.json({
      data: results,
      pagination: {
        page,
        limit,
        totalItems: total,
        totalPages,
      },
    });
  } catch (err) {
    console.error("❌ Database query error on /api/organizations:", err);
    res.status(500).json({ error: 'Failed to fetch Organizations data' });
  }
});


app.get('/api/organizations/export', async (req, res) => {
  try {
    const { whereString, params } = buildWhereClause(
      req.query,
      ['OrganizationID', 'Organization'], // Searchable fields
      ['OrganizationID', 'Organization', 'LastModifiedTimestamp'] // Filterable columns
    );

    const dataQuery = `SELECT * FROM Organizations ${whereString}`;
    const [results] = await db.query(dataQuery, params);

    if (results.length === 0) {
      return res.status(404).send("No data found to export for the given filters.");
    }

    const headers = Object.keys(results[0]);
    const csvHeader = headers.join(',');
    const csvRows = results.map(row =>
      headers.map(header => {
        const value = row[header];
        const strValue = String(value === null || value === undefined ? '' : value);
        return `"${strValue.replace(/"/g, '""')}"`;
      }).join(',')
    );
    const csvContent = [csvHeader, ...csvRows].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="organizations_export.csv"');
    res.status(200).send(csvContent);
  } catch (err) {
    console.error("❌ Database query error on /api/organizations/export:", err);
    res.status(500).json({ error: 'CSV export failed' });
  }
});

app.put('/api/organizations/:OrganizationID', async (req, res) => {
  const { OrganizationID } = req.params;
  const { Organization, LastModifiedBy } = req.body;

  if (!OrganizationID) return res.status(400).json({ error: "OrganizationID is required." });
  if (!Organization) return res.status(400).json({ error: "Organization is required." });
  if (!LastModifiedBy) return res.status(400).json({ error: "LastModifiedBy (user email) is required." });

  try {
    const query = `
      UPDATE Organizations
      SET Organization = ?, LastModifiedBy = ?, LastModifiedTimestamp = NOW()
      WHERE OrganizationID = ?
    `;
    const [result] = await db.query(query, [Organization, LastModifiedBy, OrganizationID]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: `Organization with ID ${OrganizationID} not found.` });
    }
    res.status(200).json({ message: "Organization updated successfully." });
  } catch (err) {
    console.error("❌ Database query error on /api/organizations/:OrganizationID:", err);
    res.status(500).json({ error: "Failed to update Organization." });
  }
});


app.post('/api/organizations', async (req, res) => {
  const { Organization, LastModifiedBy } = req.body;

  if (!Organization) {
    return res.status(400).json({ error: "Organization is required." });
  }
  if (!LastModifiedBy) {
    return res.status(400).json({ error: "LastModifiedBy (user email) is required." });
  }

  try {
    const query = `
      INSERT INTO Organizations (Organization, LastModifiedBy, LastModifiedTimestamp)
      VALUES (?, ?, NOW())
    `;
    const [result] = await db.query(query, [Organization, LastModifiedBy]);

    res.status(201).json({
      message: "Organization added successfully.",
      OrganizationID: result.insertId,
      Organization,
      LastModifiedBy,
      LastModifiedTimestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error("❌ Database query error on POST /api/organizations:", err);
    res.status(500).json({ error: "Failed to add Organization." });
  }
});


// --- NEW ENDPOINT FOR 'New Event Category' DROPDOWN ---
app.get('/api/new-event-category/options', async (req, res) => {
  try {
    // 1. Fetch all non-empty, distinct NewEventCategory strings from the Events table.
    const query = `
      SELECT DISTINCT NewEventCategory
      FROM Events
      WHERE NewEventCategory IS NOT NULL AND TRIM(NewEventCategory) <> ''
    `;
    const [rows] = await db.query(query);

    // 2. Process the results to get individual unique values.
    const allCategories = new Set();
    rows.forEach(row => {
      if (row.NewEventCategory) {
        row.NewEventCategory.split(',')
          .map(c => c.trim())
          .filter(c => c !== '')
          .forEach(c => allCategories.add(c));
      }
    });

    // 3. Convert the Set to a sorted array of objects for the frontend.
    const uniqueCategories = Array.from(allCategories).sort();
    const results = uniqueCategories.map(c => ({ NewEventCategory: c }));

    res.status(200).json(results);
  } catch (err) {
    console.error("❌ Database query error on /api/new-event-category/options:", err);
    res.status(500).json({ error: 'Failed to fetch new event categories for dropdown.' });
  }
});

app.get('/api/new-event-category', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1; // Default to page 1
    const limit = parseInt(req.query.limit) || 50; // Default to 50 items per page
    const offset = (page - 1) * limit;

    const filterableColumns = [
      'SrNo',
      'NewEventCategoryName',
      'LastModifiedTimestamp',
      'MARK_DISCARD',
    ];

    const { whereString, params } = buildWhereClause(
      req.query,
      ['SrNo', 'NewEventCategoryName'], // Searchable fields
      filterableColumns
    );

    const orderByString = buildOrderByClause(req.query, filterableColumns);

    // --- Count Query ---
    const countQuery = `SELECT COUNT(*) as total FROM NewEventCategory ${whereString}`;
    const [[{ total }]] = await db.query(countQuery, params);
    const totalPages = Math.ceil(total / limit);

    // --- Data Query ---
    const dataQuery = `
      SELECT * 
      FROM NewEventCategory 
      ${whereString} 
      ${orderByString} 
      LIMIT ? OFFSET ?
    `;
    const [results] = await db.query(dataQuery, [...params, limit, offset]);

    res.json({
      data: results,
      pagination: {
        page,
        limit,
        totalItems: total,
        totalPages,
      },
    });
  } catch (err) {
    console.error("❌ Database query error on /api/new-event-category:", err);
    res.status(500).json({ error: 'Failed to fetch New Event Category data' });
  }
});

app.get('/api/new-event-category/export', async (req, res) => {
  try {
    const { whereString, params } = buildWhereClause(
      req.query,
      ['SrNo', 'NewEventCategoryName'], // Searchable fields
      ['SrNo', 'NewEventCategoryName', 'LastModifiedTimestamp', 'MARK_DISCARD'] // Filterable columns
    );

    const dataQuery = `SELECT * FROM NewEventCategory ${whereString}`;
    const [results] = await db.query(dataQuery, params);

    if (results.length === 0) {
      return res.status(404).send("No data found to export for the given filters.");
    }

    const headers = Object.keys(results[0]);
    const csvHeader = headers.join(',');
    const csvRows = results.map(row =>
      headers.map(header => {
        const value = row[header];
        const strValue = String(value === null || value === undefined ? '' : value);
        return `"${strValue.replace(/"/g, '""')}"`;
      }).join(',')
    );
    const csvContent = [csvHeader, ...csvRows].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="new_event_category_export.csv"');
    res.status(200).send(csvContent);
  } catch (err) {
    console.error("❌ Database query error on /api/new-event-category/export:", err);
    res.status(500).json({ error: 'CSV export failed' });
  }
});

app.put('/api/neweventcategory/:CategoryID', async (req, res) => {
  const { SrNo } = req.params;
  const { NewEventCategoryName, LastModifiedBy, MARK_DISCARD } = req.body;

  if (!SrNo) return res.status(400).json({ error: "SrNo is required." });
  if (!NewEventCategoryName) return res.status(400).json({ error: "NewEventCategoryName is required." });
  if (!LastModifiedBy) return res.status(400).json({ error: "LastModifiedBy (user email) is required." });

  try {
    const query = `
      UPDATE NewEventCategory
      SET NewEventCategoryName = ?, LastModifiedBy = ?, LastModifiedTimestamp = NOW(), MARK_DISCARD = ?
      WHERE SrNo = ?
    `;
    const [result] = await db.query(query, [NewEventCategoryName, LastModifiedBy, MARK_DISCARD || '', SrNo]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: `Event Category with SrNo ${SrNo} not found.` });
    }
    res.status(200).json({ message: "NewEventCategoryName updated successfully." });
  } catch (err) {
    console.error("❌ Database query error on /api/new-event-category/:SrNo:", err);
    res.status(500).json({ error: "Failed to update NewEventCategoryName." });
  }
});

app.post('/api/new-event-category', async (req, res) => {
  const { NewEventCategoryName, MARK_DISCARD, LastModifiedBy } = req.body;

  if (!NewEventCategoryName) {
    return res.status(400).json({ error: "NewEventCategoryName is required." });
  }
  if (!LastModifiedBy) {
    return res.status(400).json({ error: "LastModifiedBy (user email) is required." });
  }

  try {
    const query = `
      INSERT INTO NewEventCategory (NewEventCategoryName, MARK_DISCARD, LastModifiedBy, LastModifiedTimestamp)
      VALUES (?, ?, ?, NOW())
    `;
    const [result] = await db.query(query, [NewEventCategoryName, MARK_DISCARD || "0", LastModifiedBy]);

    res.status(201).json({
      message: "New Event Category added successfully.",
      SrNo: result.insertId,
      NewEventCategoryName,
      MARK_DISCARD: MARK_DISCARD || "0",
      LastModifiedBy,
      LastModifiedTimestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error("❌ Database query error on POST /api/new-event-category:", err);
    res.status(500).json({ error: "Failed to add New Event Category." });
  }
});

// --- NEW ENDPOINT FOR 'fkCity' DROPDOWN ---
app.get('/api/cities/options', async (req, res) => {
  try {
    // 1. Fetch all non-empty, distinct fkCity strings from the NewMediaLog table.
    const query = `
      SELECT DISTINCT fkCity
      FROM NewMediaLog
      WHERE fkCity IS NOT NULL AND TRIM(fkCity) <> ''
    `;
    const [rows] = await db.query(query);

    // 2. Process the results to get individual unique values.
    const allCities = new Set();
    rows.forEach(row => {
      if (row.fkCity) {
        row.fkCity.split(',')
          .map(c => c.trim())
          .filter(c => c !== '')
          .forEach(c => allCities.add(c));
      }
    });

    // 3. Convert the Set to a sorted array of objects for the frontend.
    const uniqueCities = Array.from(allCities).sort();
    const results = uniqueCities.map(c => ({ fkCity: c }));

    res.status(200).json(results);
  } catch (err) {
    console.error("❌ Database query error on /api/cities/options:", err);
    res.status(500).json({ error: 'Failed to fetch city options.' });
  }
});

app.get('/api/new-cities', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1; // Default to page 1
    const limit = parseInt(req.query.limit) || 50; // Default to 50 items per page
    const offset = (page - 1) * limit;

    const filterableColumns = [
      'CityID',
      'City',
      'LastModifiedTimestamp',
    ];

    const { whereString, params } = buildWhereClause(
      req.query,
      ['CityID', 'City'], // Searchable fields
      filterableColumns
    );

    const orderByString = buildOrderByClause(req.query, filterableColumns);

    // --- Count Query ---
    const countQuery = `SELECT COUNT(*) as total FROM NewCities ${whereString}`;
    const [[{ total }]] = await db.query(countQuery, params);
    const totalPages = Math.ceil(total / limit);

    // --- Data Query ---
    const dataQuery = `
      SELECT * 
      FROM NewCities 
      ${whereString} 
      ${orderByString} 
      LIMIT ? OFFSET ?
    `;
    const [results] = await db.query(dataQuery, [...params, limit, offset]);

    res.json({
      data: results,
      pagination: {
        page,
        limit,
        totalItems: total,
        totalPages,
      },
    });
  } catch (err) {
    console.error("❌ Database query error on /api/new-cities:", err);
    res.status(500).json({ error: 'Failed to fetch New Cities data' });
  }
});

app.get('/api/new-cities/export', async (req, res) => {
  try {
    const { whereString, params } = buildWhereClause(
      req.query,
      ['CityID', 'City'], // Searchable fields
      ['CityID', 'City', 'LastModifiedTimestamp'] // Filterable columns
    );

    const dataQuery = `SELECT * FROM NewCities ${whereString}`;
    const [results] = await db.query(dataQuery, params);

    if (results.length === 0) {
      return res.status(404).send("No data found to export for the given filters.");
    }

    const headers = Object.keys(results[0]);
    const csvHeader = headers.join(',');
    const csvRows = results.map(row =>
      headers.map(header => {
        const value = row[header];
        const strValue = String(value === null || value === undefined ? '' : value);
        return `"${strValue.replace(/"/g, '""')}"`;
      }).join(',')
    );
    const csvContent = [csvHeader, ...csvRows].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="new_cities_export.csv"');
    res.status(200).send(csvContent);
  } catch (err) {
    console.error("❌ Database query error on /api/new-cities/export:", err);
    res.status(500).json({ error: 'CSV export failed' });
  }
});

app.put('/api/newcities/:CityID', async (req, res) => {
   const { CityID } = req.params;
  const { City, LastModifiedBy } = req.body;

  if (!CityID) return res.status(400).json({ error: "CityID is required." });
  if (!City) return res.status(400).json({ error: "City is required." });
  if (!LastModifiedBy) return res.status(400).json({ error: "LastModifiedBy (user email) is required." });

  try {
    const query = `
      UPDATE NewCities
      SET City = ?, LastModifiedBy = ?, LastModifiedTimestamp = NOW()
      WHERE CityID = ?
    `;
    const [result] = await db.query(query, [City, LastModifiedBy, CityID]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: `City with ID ${CityID} not found.` });
    }
    res.status(200).json({ message: "City updated successfully." });
  } catch (err) {
    console.error("❌ Database query error on /api/new-cities/:CityID:", err);
    res.status(500).json({ error: "Failed to update City." });
  }
});

app.post('/api/new-cities', async (req, res) => {
  const { City, LastModifiedBy } = req.body;

  if (!City) {
    return res.status(400).json({ error: "City is required." });
  }
  if (!LastModifiedBy) {
    return res.status(400).json({ error: "LastModifiedBy (user email) is required." });
  }

  try {
    const query = `
      INSERT INTO NewCities (City, LastModifiedBy, LastModifiedTimestamp)
      VALUES (?, ?, NOW())
    `;
    const [result] = await db.query(query, [City, LastModifiedBy]);

    res.status(201).json({
      message: "City added successfully.",
      CityID: result.insertId,
      City,
      LastModifiedBy,
      LastModifiedTimestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error("❌ Database query error on POST /api/new-cities:", err);
    res.status(500).json({ error: "Failed to add City." });
  }
});


// --- NEW ENDPOINT FOR 'fkCountry' DROPDOWN ---
app.get('/api/countries/options', async (req, res) => {
  try {
    // 1. Fetch all non-empty, distinct fkCountry strings from the NewMediaLog table.
    const query = `
      SELECT DISTINCT fkCountry
      FROM NewMediaLog
      WHERE fkCountry IS NOT NULL AND TRIM(fkCountry) <> ''
    `;
    const [rows] = await db.query(query);

    // 2. Process the results to get individual unique values.
    const allCountries = new Set();
    rows.forEach(row => {
      if (row.fkCountry) {
        row.fkCountry.split(',')
          .map(c => c.trim())
          .filter(c => c !== '')
          .forEach(c => allCountries.add(c));
      }
    });

    // 3. Convert the Set to a sorted array of objects for the frontend.
    const uniqueCountries = Array.from(allCountries).sort();
    const results = uniqueCountries.map(c => ({ fkCountry: c }));

    res.status(200).json(results);
  } catch (err) {
    console.error("❌ Database query error on /api/countries/options:", err);
    res.status(500).json({ error: 'Failed to fetch country options.' });
  }
});

app.get('/api/new-countries', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1; // Default to page 1
    const limit = parseInt(req.query.limit) || 50; // Default to 50 items per page
    const offset = (page - 1) * limit;

    const filterableColumns = [
      'CountryID',
      'Country',
      'LastModifiedTimestamp',
    ];

    const { whereString, params } = buildWhereClause(
      req.query,
      ['CountryID', 'Country'], // Searchable fields
      filterableColumns
    );

    const orderByString = buildOrderByClause(req.query, filterableColumns);

    // --- Count Query ---
    const countQuery = `SELECT COUNT(*) as total FROM NewCountries ${whereString}`;
    const [[{ total }]] = await db.query(countQuery, params);
    const totalPages = Math.ceil(total / limit);

    // --- Data Query ---
    const dataQuery = `
      SELECT * 
      FROM NewCountries 
      ${whereString} 
      ${orderByString} 
      LIMIT ? OFFSET ?
    `;
    const [results] = await db.query(dataQuery, [...params, limit, offset]);

    res.json({
      data: results,
      pagination: {
        page,
        limit,
        totalItems: total,
        totalPages,
      },
    });
  } catch (err) {
    console.error("❌ Database query error on /api/new-countries:", err);
    res.status(500).json({ error: 'Failed to fetch New Countries data' });
  }
});

app.get('/api/new-countries/export', async (req, res) => {
  try {
    const { whereString, params } = buildWhereClause(
      req.query,
      ['CountryID', 'Country'], // Searchable fields
      ['CountryID', 'Country', 'LastModifiedTimestamp'] // Filterable columns
    );

    const dataQuery = `SELECT * FROM NewCountries ${whereString}`;
    const [results] = await db.query(dataQuery, params);

    if (results.length === 0) {
      return res.status(404).send("No data found to export for the given filters.");
    }

    const headers = Object.keys(results[0]);
    const csvHeader = headers.join(',');
    const csvRows = results.map(row =>
      headers.map(header => {
        const value = row[header];
        const strValue = String(value === null || value === undefined ? '' : value);
        return `"${strValue.replace(/"/g, '""')}"`;
      }).join(',')
    );
    const csvContent = [csvHeader, ...csvRows].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="new_countries_export.csv"');
    res.status(200).send(csvContent);
  } catch (err) {
    console.error("❌ Database query error on /api/new-countries/export:", err);
    res.status(500).json({ error: 'CSV export failed' });
  }
});

app.put('/api/newcountries/:CountryID', async (req, res) => {
  const { CountryID } = req.params;
  const { Country, LastModifiedBy } = req.body;

  if (!CountryID) return res.status(400).json({ error: "CountryID is required." });
  if (!Country) return res.status(400).json({ error: "Country is required." });
  if (!LastModifiedBy) return res.status(400).json({ error: "LastModifiedBy (user email) is required." });

  try {
    const query = `
      UPDATE NewCountries
      SET Country = ?, LastModifiedBy = ?, LastModifiedTimestamp = NOW()
      WHERE CountryID = ?
    `;
    const [result] = await db.query(query, [Country, LastModifiedBy, CountryID]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: `Country with ID ${CountryID} not found.` });
    }
    res.status(200).json({ message: "Country updated successfully." });
  } catch (err) {
    console.error("❌ Database query error on /api/new-countries/:CountryID:", err);
    res.status(500).json({ error: "Failed to update Country." });
  }
});

app.post('/api/new-countries', async (req, res) => {
  const { Country, LastModifiedBy } = req.body;

  if (!Country) {
    return res.status(400).json({ error: "Country is required." });
  }
  if (!LastModifiedBy) {
    return res.status(400).json({ error: "LastModifiedBy (user email) is required." });
  }

  try {
    const query = `
      INSERT INTO NewCountries (Country, LastModifiedBy, LastModifiedTimestamp)
      VALUES (?, ?, NOW())
    `;
    const [result] = await db.query(query, [Country, LastModifiedBy]);

    res.status(201).json({
      message: "Country added successfully.",
      CountryID: result.insertId,
      Country,
      LastModifiedBy,
      LastModifiedTimestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error("❌ Database query error on POST /api/new-countries:", err);
    res.status(500).json({ error: "Failed to add Country." });
  }
});
// --- NEW ENDPOINT FOR 'fkState' DROPDOWN ---
app.get('/api/states/options', async (req, res) => {
  try {
    // 1. Fetch all non-empty, distinct fkState strings from the NewMediaLog table.
    const query = `
      SELECT DISTINCT fkState
      FROM NewMediaLog
      WHERE fkState IS NOT NULL AND TRIM(fkState) <> ''
    `;
    const [rows] = await db.query(query);

    // 2. Process the results to get individual unique values.
    const allStates = new Set();
    rows.forEach(row => {
      if (row.fkState) {
        row.fkState.split(',')
          .map(s => s.trim())
          .filter(s => s !== '')
          .forEach(s => allStates.add(s));
      }
    });

    // 3. Convert the Set to a sorted array of objects for the frontend.
    const uniqueStates = Array.from(allStates).sort();
    const results = uniqueStates.map(s => ({ fkState: s }));

    res.status(200).json(results);
  } catch (err) {
    console.error("❌ Database query error on /api/states/options:", err);
    res.status(500).json({ error: 'Failed to fetch state options.' });
  }
});

app.get('/api/new-states', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1; // Default to page 1
    const limit = parseInt(req.query.limit) || 50; // Default to 50 items per page
    const offset = (page - 1) * limit;

    const filterableColumns = [
      'StateID',
      'State',
      'LastModifiedTimestamp',
    ];

    const { whereString, params } = buildWhereClause(
      req.query,
      ['StateID', 'State'], // Searchable fields
      filterableColumns
    );

    const orderByString = buildOrderByClause(req.query, filterableColumns);

    // --- Count Query ---
    const countQuery = `SELECT COUNT(*) as total FROM NewStates ${whereString}`;
    const [[{ total }]] = await db.query(countQuery, params);
    const totalPages = Math.ceil(total / limit);

    // --- Data Query ---
    const dataQuery = `
      SELECT * 
      FROM NewStates 
      ${whereString} 
      ${orderByString} 
      LIMIT ? OFFSET ?
    `;
    const [results] = await db.query(dataQuery, [...params, limit, offset]);

    res.json({
      data: results,
      pagination: {
        page,
        limit,
        totalItems: total,
        totalPages,
      },
    });
  } catch (err) {
    console.error("❌ Database query error on /api/new-states:", err);
    res.status(500).json({ error: 'Failed to fetch New States data' });
  }
});

app.get('/api/new-states/export', async (req, res) => {
  try {
    const { whereString, params } = buildWhereClause(
      req.query,
      ['StateID', 'State'], // Searchable fields
      ['StateID', 'State', 'LastModifiedTimestamp'] // Filterable columns
    );

    const dataQuery = `SELECT * FROM NewStates ${whereString}`;
    const [results] = await db.query(dataQuery, params);

    if (results.length === 0) {
      return res.status(404).send("No data found to export for the given filters.");
    }

    const headers = Object.keys(results[0]);
    const csvHeader = headers.join(',');
    const csvRows = results.map(row =>
      headers.map(header => {
        const value = row[header];
        const strValue = String(value === null || value === undefined ? '' : value);
        return `"${strValue.replace(/"/g, '""')}"`;
      }).join(',')
    );
    const csvContent = [csvHeader, ...csvRows].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="new_states_export.csv"');
    res.status(200).send(csvContent);
  } catch (err) {
    console.error("❌ Database query error on /api/new-states/export:", err);
    res.status(500).json({ error: 'CSV export failed' });
  }
});

app.put('/api/newstates/:StateID', async (req, res) => {
 const { StateID } = req.params;
  const { State, LastModifiedBy } = req.body;

  if (!StateID) return res.status(400).json({ error: "StateID is required." });
  if (!State) return res.status(400).json({ error: "State is required." });
  if (!LastModifiedBy) return res.status(400).json({ error: "LastModifiedBy (user email) is required." });

  try {
    const query = `
      UPDATE NewStates
      SET State = ?, LastModifiedBy = ?, LastModifiedTimestamp = NOW()
      WHERE StateID = ?
    `;
    const [result] = await db.query(query, [State, LastModifiedBy, StateID]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: `State with ID ${StateID} not found.` });
    }
    res.status(200).json({ message: "State updated successfully." });
  } catch (err) {
    console.error("❌ Database query error on /api/newstates/:StateID:", err);
    res.status(500).json({ error: "Failed to update State." });
  }
});

app.post('/api/new-states', async (req, res) => {
  const { State, LastModifiedBy } = req.body;

  if (!State) {
    return res.status(400).json({ error: "State is required." });
  }
  if (!LastModifiedBy) {
    return res.status(400).json({ error: "LastModifiedBy (user email) is required." });
  }

  try {
    const query = `
      INSERT INTO NewStates (State, LastModifiedBy, LastModifiedTimestamp)
      VALUES (?, ?, NOW())
    `;
    const [result] = await db.query(query, [State, LastModifiedBy]);

    res.status(201).json({
      message: "State added successfully.",
      StateID: result.insertId,
      State,
      LastModifiedBy,
      LastModifiedTimestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error("❌ Database query error on POST /api/new-states:", err);
    res.status(500).json({ error: "Failed to add State." });
  }
});

// --- NEW ENDPOINT FOR 'fkOccasion' DROPDOWN ---
app.get('/api/occasion/options', async (req, res) => {
  try {
    // 1. Fetch all non-empty, distinct fkOccasion strings from the NewMediaLog table.
    const query = `
      SELECT DISTINCT fkOccasion
      FROM NewMediaLog
      WHERE fkOccasion IS NOT NULL AND TRIM(fkOccasion) <> ''
    `;
    const [rows] = await db.query(query);

    // 2. Process the results to get individual unique values.
    const allOccasions = new Set();
    rows.forEach(row => {
      if (row.fkOccasion) {
        row.fkOccasion.split(',')
          .map(o => o.trim())
          .filter(o => o !== '')
          .forEach(o => allOccasions.add(o));
      }
    });

    // 3. Convert the Set to a sorted array of objects for the frontend.
    const uniqueOccasions = Array.from(allOccasions).sort();
    const results = uniqueOccasions.map(o => ({ fkOccasion: o }));

    res.status(200).json(results);
  } catch (err) {
    console.error("❌ Database query error on /api/occasion/options:", err);
    res.status(500).json({ error: 'Failed to fetch occasion options.' });
  }
});

app.get('/api/occasions', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1; // Default to page 1
    const limit = parseInt(req.query.limit) || 50; // Default to 50 items per page
    const offset = (page - 1) * limit;

    const filterableColumns = [
      'OccasionID',
      'Occasion',
      'LastModifiedTimestamp',
    ];

    const { whereString, params } = buildWhereClause(
      req.query,
      ['OccasionID', 'Occasion'], // Searchable fields
      filterableColumns
    );

    const orderByString = buildOrderByClause(req.query, filterableColumns);

    // --- Count Query ---
    const countQuery = `SELECT COUNT(*) as total FROM Occasions ${whereString}`;
    const [[{ total }]] = await db.query(countQuery, params);
    const totalPages = Math.ceil(total / limit);

    // --- Data Query ---
    const dataQuery = `
      SELECT * 
      FROM Occasions 
      ${whereString} 
      ${orderByString} 
      LIMIT ? OFFSET ?
    `;
    const [results] = await db.query(dataQuery, [...params, limit, offset]);

    res.json({
      data: results,
      pagination: {
        page,
        limit,
        totalItems: total,
        totalPages,
      },
    });
  } catch (err) {
    console.error("❌ Database query error on /api/occasions:", err);
    res.status(500).json({ error: 'Failed to fetch Occasions data' });
  }
});

app.get('/api/occasions/export', async (req, res) => {
  try {
    const { whereString, params } = buildWhereClause(
      req.query,
      ['OccasionID', 'Occasion'], // Searchable fields
      ['OccasionID', 'Occasion', 'LastModifiedTimestamp'] // Filterable columns
    );

    const dataQuery = `SELECT * FROM Occasions ${whereString}`;
    const [results] = await db.query(dataQuery, params);

    if (results.length === 0) {
      return res.status(404).send("No data found to export for the given filters.");
    }

    const headers = Object.keys(results[0]);
    const csvHeader = headers.join(',');
    const csvRows = results.map(row =>
      headers.map(header => {
        const value = row[header];
        const strValue = String(value === null || value === undefined ? '' : value);
        return `"${strValue.replace(/"/g, '""')}"`;
      }).join(',')
    );
    const csvContent = [csvHeader, ...csvRows].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="occasions_export.csv"');
    res.status(200).send(csvContent);
  } catch (err) {
    console.error("❌ Database query error on /api/occasions/export:", err);
    res.status(500).json({ error: 'CSV export failed' });
  }
});

app.put('/api/occasions/:OccasionID', async (req, res) => {
   const { OccasionID } = req.params;
  const { Occasion, LastModifiedBy } = req.body;

  if (!OccasionID) return res.status(400).json({ error: "OccasionID is required." });
  if (!Occasion) return res.status(400).json({ error: "Occasion is required." });
  if (!LastModifiedBy) return res.status(400).json({ error: "LastModifiedBy (user email) is required." });

  try {
    const query = `
      UPDATE Occasions
      SET Occasion = ?, LastModifiedBy = ?, LastModifiedTimestamp = NOW()
      WHERE OccasionID = ?
    `;
    const [result] = await db.query(query, [Occasion, LastModifiedBy, OccasionID]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: `Occasion with ID ${OccasionID} not found.` });
    }
    res.status(200).json({ message: "Occasion updated successfully." });
  } catch (err) {
    console.error("❌ Database query error on /api/occasions/:OccasionID:", err);
    res.status(500).json({ error: "Failed to update Occasion." });
  }
});

app.post('/api/occasions', async (req, res) => {
  const { Occasion, LastModifiedBy } = req.body;

  if (!Occasion) {
    return res.status(400).json({ error: "Occasion is required." });
  }
  if (!LastModifiedBy) {
    return res.status(400).json({ error: "LastModifiedBy (user email) is required." });
  }

  try {
    const query = `
      INSERT INTO Occasions (Occasion, LastModifiedBy, LastModifiedTimestamp)
      VALUES (?, ?, NOW())
    `;
    const [result] = await db.query(query, [Occasion, LastModifiedBy]);

    res.status(201).json({
      message: "Occasion added successfully.",
      OccasionID: result.insertId,
      Occasion,
      LastModifiedBy,
      LastModifiedTimestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error("❌ Database query error on POST /api/occasions:", err);
    res.status(500).json({ error: "Failed to add Occasion." });
  }
});
// --- NEW ENDPOINT FOR 'TopicSource' & 'NumberSource' DROPDOWN ---
app.get('/api/number-source/options', async (req, res) => {
  try {
    const query = `
      SELECT DISTINCT NumberSource
      FROM NewMediaLog
      WHERE NumberSource IS NOT NULL AND TRIM(NumberSource) <> ''
    `;
    const [rows] = await db.query(query);

    const allSources = new Set();
    rows.forEach(row => {
      if (row.NumberSource) {
        row.NumberSource.split(',')
          .map(s => s.trim())
          .filter(s => s !== '')
          .forEach(s => allSources.add(s));
      }
    });

    const uniqueSources = Array.from(allSources).sort();
    const results = uniqueSources.map(s => ({ NumberSource: s }));

    res.status(200).json(results);
  } catch (err) {
    console.error("❌ Database query error on /api/number-source/options:", err);
    res.status(500).json({ error: 'Failed to fetch number source options.' });
  }
});


app.get('/api/topic-source/options', async (req, res) => {
  try {
    const query = `
      SELECT DISTINCT TopicSource
      FROM NewMediaLog
      WHERE TopicSource IS NOT NULL AND TRIM(TopicSource) <> ''
    `;
    const [rows] = await db.query(query);

    const allSources = new Set();
    rows.forEach(row => {
      if (row.TopicSource) {
        row.TopicSource.split(',')
          .map(s => s.trim())
          .filter(s => s !== '')
          .forEach(s => allSources.add(s));
      }
    });

    const uniqueSources = Array.from(allSources).sort();
    const results = uniqueSources.map(s => ({ TopicSource: s }));

    res.status(200).json(results);
  } catch (err) {
    console.error("❌ Database query error on /api/topic-source/options:", err);
    res.status(500).json({ error: 'Failed to fetch topic source options.' });
  }
});

app.get('/api/topic-number-source', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1; // Default to page 1
    const limit = parseInt(req.query.limit) || 50; // Default to 50 items per page
    const offset = (page - 1) * limit;

    const filterableColumns = [
      'TNID',
      'TNName',
    ];

    const { whereString, params } = buildWhereClause(
      req.query,
      ['TNID', 'TNName'], // Searchable fields
      filterableColumns
    );

    const orderByString = buildOrderByClause(req.query, filterableColumns);

    // --- Count Query ---
    const countQuery = `SELECT COUNT(*) as total FROM TopicNumberSource ${whereString}`;
    const [[{ total }]] = await db.query(countQuery, params);
    const totalPages = Math.ceil(total / limit);

    // --- Data Query ---
    const dataQuery = `
      SELECT * 
      FROM TopicNumberSource 
      ${whereString} 
      ${orderByString} 
      LIMIT ? OFFSET ?
    `;
    const [results] = await db.query(dataQuery, [...params, limit, offset]);

    res.json({
      data: results,
      pagination: {
        page,
        limit,
        totalItems: total,
        totalPages,
      },
    });
  } catch (err) {
    console.error("❌ Database query error on /api/topic-number-source:", err);
    res.status(500).json({ error: 'Failed to fetch Topic Number Source data' });
  }
});

app.put('/api/topicnumbersource/:TNID', async (req, res) => {
  const { TNID } = req.params;
  const { TNName, LastModifiedBy } = req.body;

  if (!TNID) return res.status(400).json({ error: "TNID is required." });
  if (!TNName) return res.status(400).json({ error: "TNName is required." });
  if (!LastModifiedBy) return res.status(400).json({ error: "LastModifiedBy (user email) is required." });

  try {
    const query = `
      UPDATE TopicNumberSource
      SET TNName = ?, LastModifiedBy = ?, LastModifiedTimestamp = NOW()
      WHERE TNID = ?
    `;
    const [result] = await db.query(query, [TNName, LastModifiedBy, TNID]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: `Topic Number with ID ${TNID} not found.` });
    }
    res.status(200).json({ message: "TNName updated successfully." });
  } catch (err) {
    console.error("❌ Database query error on /api/topic-number-source/:TNID:", err);
    res.status(500).json({ error: "Failed to update TNName." });
  }
});

app.post('/api/topic-number-source', async (req, res) => {
  const { TNName, LastModifiedBy } = req.body;

  if (!TNName) {
    return res.status(400).json({ error: "TNName is required." });
  }
  if (!LastModifiedBy) {
    return res.status(400).json({ error: "LastModifiedBy (user email) is required." });
  }

  try {
    const query = `
      INSERT INTO TopicNumberSource (TNName, LastModifiedBy, LastModifiedTimestamp)
      VALUES (?, ?, NOW())
    `;
    const [result] = await db.query(query, [TNName, LastModifiedBy]);

    res.status(201).json({
      message: "Topic Number Source added successfully.",
      TNID: result.insertId,
      TNName,
      LastModifiedBy,
      LastModifiedTimestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error("❌ Database query error on POST /api/topic-number-source:", err);
    res.status(500).json({ error: "Failed to add Topic Number Source." });
  }
});
// ✅ ADDED: NEW ENDPOINT TO UPDATE LAST ACTIVE STATUS
app.put('/api/users/:id/last-active', async (req, res) => {
    const { id } = req.params;
    const { lastActive } = req.body; // Expecting an ISO string like "2023-10-27T10:00:00.000Z"

    if (!id || !lastActive) {
        return res.status(400).json({ error: "User ID and lastActive timestamp are required." });
    }

    try {
        const sheets = google.sheets({ version: "v4", auth: await auth.getClient() });
        const getRowsResponse = await sheets.spreadsheets.values.get({
            spreadsheetId: SHEET_ID,
            range: 'Sheet1!A:A', // Read all IDs in column A
        });

        const ids = getRowsResponse.data.values;
        if (!ids) {
            return res.status(404).json({ error: "User not found in sheet." });
        }
        
        // Find the index of the user's ID, skipping the header row
        const rowIndex = ids.slice(1).findIndex(row => row[0] === id);

        if (rowIndex === -1) {
            return res.status(404).json({ error: "User not found." });
        }

        // The sheet row number is the 0-based index + 2 (1 for header, 1 for 1-based range)
        const sheetRowNumber = rowIndex + 2;

        await sheets.spreadsheets.values.update({
            spreadsheetId: SHEET_ID,
            range: `Sheet1!G${sheetRowNumber}`, // Update cell in Column G (Last Active)
            valueInputOption: 'USER_ENTERED',
            resource: {
                values: [[lastActive]],
            },
        });

        res.status(200).json({ message: 'Last active timestamp updated successfully.' });
    } catch (err) {
        console.error("Error updating last active status:", err);
        res.status(500).json({ error: "Failed to update last active status." });
    }
});


app.get('/api/topic-number-source/export', async (req, res) => {
  try {
    const { whereString, params } = buildWhereClause(
      req.query,
      ['TNID', 'TNName'], // Searchable fields
      ['TNID', 'TNName'] // Filterable columns
    );

    const dataQuery = `SELECT * FROM TopicNumberSource ${whereString}`;
    const [results] = await db.query(dataQuery, params);

    if (results.length === 0) {
      return res.status(404).send("No data found to export for the given filters.");
    }

    const headers = Object.keys(results[0]);
    const csvHeader = headers.join(',');
    const csvRows = results.map(row =>
      headers.map(header => {
        const value = row[header];
        const strValue = String(value === null || value === undefined ? '' : value);
        return `"${strValue.replace(/"/g, '""')}"`;
      }).join(',')
    );
    const csvContent = [csvHeader, ...csvRows].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="topic_number_source_export.csv"');
    res.status(200).send(csvContent);
  } catch (err) {
    console.error("❌ Database query error on /api/topic-number-source/export:", err);
    res.status(500).json({ error: 'CSV export failed' });
  }
});



// --- NEW ENDPOINT FOR 'TimeList' DROPDOWN ---
app.get('/api/time-of-day/options', async (req, res) => {
  try {
    // 1. Fetch all non-empty, distinct TimeOfDay strings from the NewMediaLog table.
    const query = `
      SELECT DISTINCT TimeOfDay
      FROM NewMediaLog
      WHERE TimeOfDay IS NOT NULL AND TRIM(TimeOfDay) <> ''
    `;
    const [rows] = await db.query(query);

    // 2. Process the results to get individual unique values.
    const allTimes = new Set();
    rows.forEach(row => {
      if (row.TimeOfDay) {
        row.TimeOfDay.split(',')
          .map(t => t.trim())
          .filter(t => t !== '')
          .forEach(t => allTimes.add(t));
      }
    });

    // 3. Convert the Set to a sorted array of objects for the frontend.
    const uniqueTimes = Array.from(allTimes).sort();
    const results = uniqueTimes.map(t => ({ TimeOfDay: t }));

    res.status(200).json(results);
  } catch (err) {
    console.error("❌ Database query error on /api/time-of-day/options:", err);
    res.status(500).json({ error: 'Failed to fetch Time of Day options.' });
  }
});

app.get('/api/time-of-day', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;

    const filterableColumns = [
      'TimeID',
      'TimeList',
    ];

    const { whereString, params } = buildWhereClause(
      req.query,
      ['TimeID', 'TimeList'], // Searchable fields
      filterableColumns
    );

    const orderByString = buildOrderByClause(req.query, filterableColumns);

    // --- Count Query ---
    const countQuery = `SELECT COUNT(*) as total FROM TimeOfDays ${whereString}`;
    const [[{ total }]] = await db.query(countQuery, params);
    const totalPages = Math.ceil(total / limit);

    // --- Data Query ---
    const dataQuery = `
      SELECT * 
      FROM TimeOfDays 
      ${whereString} 
      ${orderByString} 
      LIMIT ? OFFSET ?
    `;
    const [results] = await db.query(dataQuery, [...params, limit, offset]);

    res.json({
      data: results,
      pagination: {
        page,
        limit,
        totalItems: total,
        totalPages,
      },
    });
  } catch (err) {
    console.error("❌ Database query error on /api/time-of-day:", err);
    res.status(500).json({ error: 'Failed to fetch Time of Day data' });
  }
});


app.get('/api/time-of-day/export', async (req, res) => {
  try {
    const { whereString, params } = buildWhereClause(
      req.query,
      ['TimeID', 'TimeList'], // Searchable fields
      ['TimeID', 'TimeList']  // Filterable columns
    );

    const dataQuery = `SELECT * FROM TimeOfDays ${whereString}`;
    const [results] = await db.query(dataQuery, params);

    if (results.length === 0) {
      return res.status(404).send("No data found to export for the given filters.");
    }

    const headers = Object.keys(results[0]);
    const csvHeader = headers.join(',');
    const csvRows = results.map(row =>
      headers.map(header => {
        const value = row[header];
        const strValue = String(value === null || value === undefined ? '' : value);
        return `"${strValue.replace(/"/g, '""')}"`;
      }).join(',')
    );
    const csvContent = [csvHeader, ...csvRows].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="time_of_day_export.csv"');
    res.status(200).send(csvContent);
  } catch (err) {
    console.error("❌ Database query error on /api/time-of-day/export:", err);
    res.status(500).json({ error: 'CSV export failed' });
  }
});


app.put('/api/time-of-day/:TimeID', async (req, res) => {
    const { TimeID } = req.params;
  const { TimeList, LastModifiedBy } = req.body;

  if (!TimeID) {
    return res.status(400).json({ error: "Time ID (TimeID) is required." });
  }
  if (!TimeList) {
    return res.status(400).json({ error: "TimeList is required." });
  }
  if (!LastModifiedBy) {
    return res.status(400).json({ error: "LastModifiedBy (user email) is required." });
  }

  try {
    const query = `
      UPDATE TimeOfDays
      SET TimeList = ?, LastModifiedBy = ?, LastModifiedTimestamp = NOW()
      WHERE TimeID = ?
    `;

    const [result] = await db.query(query, [TimeList, LastModifiedBy, TimeID]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: `Time of Day with ID ${TimeID} not found.` });
    }

    res.status(200).json({ message: "Time of Day updated successfully." });
  } catch (err) {
    console.error("❌ Database query error on /api/time-of-day/:TimeID:", err);
    res.status(500).json({ error: "Failed to update Time of Day." });
  }
});

app.post('/api/time-of-day', async (req, res) => {
  const { TimeList, LastModifiedBy } = req.body;

  if (!TimeList) {
    return res.status(400).json({ error: "TimeList is required." });
  }
  if (!LastModifiedBy) {
    return res.status(400).json({ error: "LastModifiedBy (user email) is required." });
  }

  try {
    const query = `
      INSERT INTO TimeOfDays (TimeList, LastModifiedBy, LastModifiedTimestamp)
      VALUES (?, ?, NOW())
    `;
    const [result] = await db.query(query, [TimeList, LastModifiedBy]);

    res.status(201).json({
      message: "Time of Day added successfully.",
      TimeID: result.insertId,
      TimeList,
      LastModifiedBy,
      LastModifiedTimestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error("❌ Database query error on POST /api/time-of-day:", err);
    res.status(500).json({ error: "Failed to add Time of Day." });
  }
});
// --- NEW ENDPOINT FOR 'AuxFileType' DROPDOWN ---
app.get('/api/aux-file-type/options', async (req, res) => {
  try {
    // 1. Fetch all non-empty, distinct AuxFileType strings from the AuxFiles table.
    const query = `
      SELECT DISTINCT AuxFileType
      FROM AuxFiles
      WHERE AuxFileType IS NOT NULL AND TRIM(AuxFileType) <> ''
    `;
    const [rows] = await db.query(query);

    // 2. Process the results in Node.js to get individual unique values.
    const allTypes = new Set();
    rows.forEach(row => {
      if (row.AuxFileType) {
        row.AuxFileType.split(',')
          .map(v => v.trim())
          .filter(v => v !== '')
          .forEach(v => allTypes.add(v));
      }
    });

    // 3. Convert the Set to a sorted array of objects, as expected by the frontend.
    const uniqueTypes = Array.from(allTypes).sort();
    const results = uniqueTypes.map(v => ({ AuxFileType: v }));

    res.status(200).json(results);
  } catch (err) {
    console.error("❌ Database query error on /api/aux-file-type/options:", err);
    res.status(500).json({ error: 'Failed to fetch Aux File Type options.' });
  }
});


app.get('/api/aux-file-type', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;

    const filterableColumns = [
      'AuxTypeID',
      'AuxFileType',
      'LastModifiedTimestamp',
    ];

    const { whereString, params } = buildWhereClause(
      req.query,
      ['AuxTypeID', 'AuxFileType'], // Searchable fields
      filterableColumns
    );

    const orderByString = buildOrderByClause(req.query, filterableColumns);

    // --- Count Query ---
    const countQuery = `SELECT COUNT(*) as total FROM AuxFileType ${whereString}`;
    const [[{ total }]] = await db.query(countQuery, params);
    const totalPages = Math.ceil(total / limit);

    // --- Data Query ---
    const dataQuery = `
      SELECT * 
      FROM AuxFileType 
      ${whereString} 
      ${orderByString} 
      LIMIT ? OFFSET ?
    `;
    const [results] = await db.query(dataQuery, [...params, limit, offset]);

    res.json({
      data: results,
      pagination: {
        page,
        limit,
        totalItems: total,
        totalPages,
      },
    });
  } catch (err) {
    console.error("❌ Database query error on /api/aux-file-type:", err);
    res.status(500).json({ error: 'Failed to fetch Aux File Type data' });
  }
});


app.get('/api/aux-file-type/export', async (req, res) => {
  try {
    const { whereString, params } = buildWhereClause(
      req.query,
      ['AuxTypeID', 'AuxFileType'], // Searchable fields
      ['AuxTypeID', 'AuxFileType', 'LastModifiedTimestamp'] // Filterable columns
    );

    const dataQuery = `SELECT * FROM AuxFileType ${whereString}`;
    const [results] = await db.query(dataQuery, params);

    if (results.length === 0) {
      return res.status(404).send("No data found to export for the given filters.");
    }

    const headers = Object.keys(results[0]);
    const csvHeader = headers.join(',');
    const csvRows = results.map(row =>
      headers.map(header => {
        const value = row[header];
        const strValue = String(value === null || value === undefined ? '' : value);
        return `"${strValue.replace(/"/g, '""')}"`;
      }).join(',')
    );
    const csvContent = [csvHeader, ...csvRows].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="aux_file_type_export.csv"');
    res.status(200).send(csvContent);
  } catch (err) {
    console.error("❌ Database query error on /api/aux-file-type/export:", err);
    res.status(500).json({ error: 'CSV export failed' });
  }
});


app.put('/api/aux-file-type/:AuxTypeID', async (req, res) => {
  const { AuxTypeID } = req.params;
  const { AuxFileType } = req.body;

  if (!AuxTypeID) {
    return res.status(400).json({ error: "Aux File Type ID (AuxTypeID) is required." });
  }

  if (!AuxFileType) {
    return res.status(400).json({ error: "AuxFileType is required." });
  }

  try {
    const query = `
      UPDATE AuxFileType
      SET AuxFileType = ?, LastModifiedTimestamp = NOW()
      WHERE AuxTypeID = ?
    `;

    const [result] = await db.query(query, [AuxFileType, AuxTypeID]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: `Aux File Type with ID ${AuxTypeID} not found.` });
    }

    res.status(200).json({ message: "AuxFileType updated successfully." });
  } catch (err) {
    console.error("❌ Database query error on /api/aux-file-type/:AuxTypeID:", err);
    res.status(500).json({ error: "Failed to update AuxFileType." });
  }
});

app.post('/api/aux-file-type', async (req, res) => {
  const { AuxFileType, LastModifiedBy } = req.body;

  if (!AuxFileType) {
    return res.status(400).json({ error: "AuxFileType is required." });
  }
  if (!LastModifiedBy) {
    return res.status(400).json({ error: "LastModifiedBy (user email) is required." });
  }

  try {
    const query = `
      INSERT INTO AuxFileType (AuxFileType, LastModifiedBy, LastModifiedTimestamp)
      VALUES (?, ?, NOW())
    `;
    const [result] = await db.query(query, [AuxFileType, LastModifiedBy]);

    res.status(201).json({
      message: "Aux File Type added successfully.",
      AuxTypeID: result.insertId,
      AuxFileType,
      LastModifiedBy,
      LastModifiedTimestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error("❌ Database query error on POST /api/aux-file-type:", err);
    res.status(500).json({ error: "Failed to add Aux File Type." });
  }
});

// --- NEW ENDPOINT FOR 'Keywords' DROPDOWN ---
app.get('/api/keywords/options', async (req, res) => {
  try {
    // 1. Fetch all non-empty, distinct keyword strings from the database.
    const query = `
      SELECT DISTINCT Keywords 
      FROM NewMediaLog 
      WHERE Keywords IS NOT NULL AND TRIM(Keywords) <> ''
    `;
    const [rows] = await db.query(query);

    // 2. Process the results in Node.js to get individual unique keywords.
    const allKeywords = new Set();

    rows.forEach(row => {
      if (row.Keywords) {
        // Split by comma, trim whitespace from each part, and filter out any empty strings that might result.
        const keywords = row.Keywords.split(',')
                                     .map(kw => kw.trim())
                                     .filter(kw => kw !== '');
        // Add each individual keyword to the Set to ensure uniqueness.
        keywords.forEach(kw => allKeywords.add(kw));
      }
    });

    // 3. Convert the Set to a sorted array of objects, as expected by the frontend.
    const uniqueKeywords = Array.from(allKeywords).sort();
    const results = uniqueKeywords.map(kw => ({ Keywords: kw }));

    res.status(200).json(results);

  } catch (err) {
    console.error("❌ Database query error on /api/keywords/options:", err);
    res.status(500).json({ error: 'Failed to fetch Keywords options.' });
  }
});


app.get('/api/dimension/options', async (req, res) => {
  try {
    // 1. Fetch all non-empty, distinct dimension strings from the database.
    const query = `
      SELECT DISTINCT Dimension
      FROM DigitalRecordings
      WHERE Dimension IS NOT NULL AND TRIM(Dimension) <> ''
    `;
    const [rows] = await db.query(query);

    // 2. Process the results in Node.js to get individual unique dimensions.
    const allDimensions = new Set();

    rows.forEach(row => {
      if (row.Dimension) {
        // Split by comma, trim whitespace, and filter out empty strings.
        const dims = row.Dimension.split(',')
                                  .map(d => d.trim())
                                  .filter(d => d !== '');
        dims.forEach(d => allDimensions.add(d));
      }
    });

    // 3. Convert the Set to a sorted array of objects, as expected by the frontend.
    const uniqueDimensions = Array.from(allDimensions).sort();
    const results = uniqueDimensions.map(d => ({ Dimension: d }));

    res.status(200).json(results);

  } catch (err) {
    console.error("❌ Database query error on /api/dimension/options:", err);
    res.status(500).json({ error: 'Failed to fetch Dimension options.' });
  }
});

app.get('/api/production-bucket/options', async (req, res) => {
  try {
    // 1. Fetch all non-empty, distinct production bucket strings from the database.
    const query = `
      SELECT DISTINCT ProductionBucket
      FROM DigitalRecordings
      WHERE ProductionBucket IS NOT NULL AND TRIM(ProductionBucket) <> ''
    `;
    const [rows] = await db.query(query);

    // 2. Process the results in Node.js to get individual unique production buckets.
    const allBuckets = new Set();

    rows.forEach(row => {
      if (row.ProductionBucket) {
        // Split by comma, trim whitespace, and filter out empty strings.
        const buckets = row.ProductionBucket.split(',')
                                  .map(b => b.trim())
                                  .filter(b => b !== '');
        buckets.forEach(b => allBuckets.add(b));
      }
    });

    // 3. Convert the Set to a sorted array of objects, as expected by the frontend.
    const uniqueBuckets = Array.from(allBuckets).sort();
    const results = uniqueBuckets.map(b => ({ ProductionBucket: b }));

    res.status(200).json(results);

  } catch (err) {
    console.error("❌ Database query error on /api/production-bucket/options:", err);
    res.status(500).json({ error: 'Failed to fetch ProductionBucket options.' });
  }
});

// --- NEW ENDPOINT FOR 'PreservationStatus' DROPDOWN ---
app.get('/api/preservation-status/options', async (req, res) => {
  try {
    const query = `
      SELECT DISTINCT PreservationStatus
      FROM DigitalRecordings
      WHERE PreservationStatus IS NOT NULL AND TRIM(PreservationStatus) <> ''
    `;
    const [rows] = await db.query(query);

    const allStatuses = new Set();
    rows.forEach(row => {
      if (row.PreservationStatus) {
        row.PreservationStatus.split(',')
          .map(s => s.trim())
          .filter(s => s !== '')
          .forEach(s => allStatuses.add(s));
      }
    });

    const uniqueStatuses = Array.from(allStatuses).sort();
    const results = uniqueStatuses.map(s => ({ PreservationStatus: s }));

    res.status(200).json(results);
  } catch (err) {
    console.error("❌ Database query error on /api/preservation-status/options:", err);
    res.status(500).json({ error: 'Failed to fetch PreservationStatus options.' });
  }
});

// --- NEW ENDPOINT FOR 'Teams' DROPDOWN ---
app.get('/api/teams/options', async (req, res) => {
  try {
    const query = `
      SELECT DISTINCT Teams
      FROM DigitalRecordings
      WHERE Teams IS NOT NULL AND TRIM(Teams) <> ''
    `;
    const [rows] = await db.query(query);

    const allTeams = new Set();
    rows.forEach(row => {
      if (row.Teams) {
        row.Teams.split(',')
          .map(t => t.trim())
          .filter(t => t !== '')
          .forEach(t => allTeams.add(t));
      }
    });

    const uniqueTeams = Array.from(allTeams).sort();
    const results = uniqueTeams.map(t => ({ Teams: t }));

    res.status(200).json(results);
  } catch (err) {
    console.error("❌ Database query error on /api/teams/options:", err);
    res.status(500).json({ error: 'Failed to fetch Teams options.' });
  }
});


app.get('/api/topic-given-by/options', async (req, res) => {
  try {
    // 1. Fetch all non-empty, distinct TopicGivenBy strings from the database.
    const query = `
      SELECT DISTINCT TopicGivenBy
      FROM NewMediaLog
      WHERE TopicGivenBy IS NOT NULL AND TRIM(TopicGivenBy) <> ''
    `;
    const [rows] = await db.query(query);

    // 2. Process the results in Node.js to get individual unique values.
    const allValues = new Set();

    rows.forEach(row => {
      if (row.TopicGivenBy) {
        row.TopicGivenBy.split(',')
          .map(v => v.trim())
          .filter(v => v !== '')
          .forEach(v => allValues.add(v));
      }
    });

    // 3. Convert the Set to a sorted array of objects, as expected by the frontend.
    const uniqueValues = Array.from(allValues).sort();
    const results = uniqueValues.map(v => ({ TopicGivenBy: v }));

    res.status(200).json(results);

  } catch (err) {
    console.error("❌ Database query error on /api/topic-given-by/options:", err);
    res.status(500).json({ error: 'Failed to fetch Topic Given By options.' });
  }
});

app.get('/api/topic-given-by', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;

    const filterableColumns = [
      'TGBID',
      'TGB_Name',
      'LastModifiedBy',
      'LastModifiedTs',
    ];

    const { whereString, params } = buildWhereClause(
      req.query,
      ['TGBID', 'TGB_Name', 'LastModifiedBy'], // Searchable fields
      filterableColumns
    );

    const orderByString = buildOrderByClause(req.query, filterableColumns);

    // --- Count Query ---
    const countQuery = `SELECT COUNT(*) as total FROM TopicGivenBy ${whereString}`;
    const [[{ total }]] = await db.query(countQuery, params);
    const totalPages = Math.ceil(total / limit);

    // --- Data Query ---
    const dataQuery = `
      SELECT * 
      FROM TopicGivenBy 
      ${whereString} 
      ${orderByString} 
      LIMIT ? OFFSET ?
    `;
    const [results] = await db.query(dataQuery, [...params, limit, offset]);

    res.json({
      data: results,
      pagination: {
        page,
        limit,
        totalItems: total,
        totalPages,
      },
    });
  } catch (err) {
    console.error("❌ Database query error on /api/topic-given-by:", err);
    res.status(500).json({ error: 'Failed to fetch Topic Given By data' });
  }
});

app.get('/api/topic-given-by/export', async (req, res) => {
  try {
    const { whereString, params } = buildWhereClause(
      req.query,
      ['TGBID', 'TGB_Name', 'LastModifiedBy'], // Searchable fields
      ['TGBID', 'TGB_Name', 'LastModifiedBy', 'LastModifiedTs'] // Filterable columns
    );

    const dataQuery = `SELECT * FROM TopicGivenBy ${whereString}`;
    const [results] = await db.query(dataQuery, params);

    if (results.length === 0) {
      return res.status(404).send("No data found to export for the given filters.");
    }

    const headers = Object.keys(results[0]);
    const csvHeader = headers.join(',');
    const csvRows = results.map(row =>
      headers.map(header => {
        const value = row[header];
        const strValue = String(value === null || value === undefined ? '' : value);
        return `"${strValue.replace(/"/g, '""')}"`;
      }).join(',')
    );
    const csvContent = [csvHeader, ...csvRows].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="topic_given_by_export.csv"');
    res.status(200).send(csvContent);
  } catch (err) {
    console.error("❌ Database query error on /api/topic-given-by/export:", err);
    res.status(500).json({ error: 'CSV export failed' });
  }
});

app.put('/api/topic-given-by/:TGBID', async (req, res) => {
  const { TGBID } = req.params;
  const { TGB_Name, LastModifiedBy } = req.body;

  if (!TGBID) {
    return res.status(400).json({ error: "TGBID is required." });
  }
  if (!TGB_Name) {
    return res.status(400).json({ error: "TGB_Name is required." });
  }

  try {
    const query = `
      UPDATE TopicGivenBy
      SET TGB_Name = ?, LastModifiedBy = ?, LastModifiedTs = NOW()
      WHERE TGBID = ?
    `;

    const [result] = await db.query(query, [TGB_Name, LastModifiedBy || '', TGBID]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: `Topic Given By with ID ${TGBID} not found.` });
    }

    res.status(200).json({ message: "Topic Given By updated successfully." });
  } catch (err) {
    console.error("❌ Database query error on /api/topic-given-by/:TGBID:", err);
    res.status(500).json({ error: "Failed to update Topic Given By." });
  }
});

app.post('/api/topic-given-by', async (req, res) => {
  const { TGB_Name, LastModifiedBy } = req.body;

  if (!TGB_Name) {
    return res.status(400).json({ error: "TGB_Name is required." });
  }
  if (!LastModifiedBy) {
    return res.status(400).json({ error: "LastModifiedBy (user email) is required." });
  }

  try {
    const query = `
      INSERT INTO TopicGivenBy (TGB_Name, LastModifiedBy, LastModifiedTs)
      VALUES (?, ?, NOW())
    `;
    const [result] = await db.query(query, [TGB_Name, LastModifiedBy]);

    res.status(201).json({
      message: "Topic Given By added successfully.",
      TGBID: result.insertId,
      TGB_Name,
      LastModifiedBy,
      LastModifiedTs: new Date().toISOString()
    });
  } catch (err) {
    console.error("❌ Database query error on POST /api/topic-given-by:", err);
    res.status(500).json({ error: "Failed to add Topic Given By." });
  }
});
app.get('/api/segment-category/options', async (req, res) => {
  try {
    // 1. Fetch all non-empty, distinct segment category strings from the database.
    const query = `
      SELECT DISTINCT \`Segment Category\`
      FROM NewMediaLog
      WHERE \`Segment Category\` IS NOT NULL AND TRIM(\`Segment Category\`) <> ''
    `;
    const [rows] = await db.query(query);

    // 2. Process the results in Node.js to get individual unique segment categories.
    const allCategories = new Set();

    rows.forEach(row => {
      if (row['Segment Category']) {
        // Split by comma, trim whitespace, and filter out empty strings.
        const cats = row['Segment Category'].split(',')
          .map(c => c.trim())
          .filter(c => c !== '');
        cats.forEach(c => allCategories.add(c));
      }
    });

    // 3. Convert the Set to a sorted array of objects, as expected by the frontend.
    const uniqueCategories = Array.from(allCategories).sort();
    const results = uniqueCategories.map(c => ({ 'Segment Category': c }));

    res.status(200).json(results);

  } catch (err) {
    console.error("❌ Database query error on /api/segment-category/options:", err);
    res.status(500).json({ error: 'Failed to fetch Segment Category options.' });
  }
});


app.get('/api/segment-category', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;

    const filterableColumns = [
      'SegCatID',
      'SegCatName',
      'LastModifiedBy',
      'LastModifiedTs',
    ];

    const { whereString, params } = buildWhereClause(
      req.query,
      ['SegCatID', 'SegCatName', 'LastModifiedBy'], // Searchable fields
      filterableColumns
    );

    const orderByString = buildOrderByClause(req.query, filterableColumns);

    // --- Count Query ---
    const countQuery = `SELECT COUNT(*) as total FROM SegmentCategory ${whereString}`;
    const [[{ total }]] = await db.query(countQuery, params);
    const totalPages = Math.ceil(total / limit);

    // --- Data Query ---
    const dataQuery = `
      SELECT * 
      FROM SegmentCategory 
      ${whereString} 
      ${orderByString} 
      LIMIT ? OFFSET ?
    `;
    const [results] = await db.query(dataQuery, [...params, limit, offset]);

    res.json({
      data: results,
      pagination: {
        page,
        limit,
        totalItems: total,
        totalPages,
      },
    });
  } catch (err) {
    console.error("❌ Database query error on /api/segment-category:", err);
    res.status(500).json({ error: 'Failed to fetch Segment Category data' });
  }
});

app.get('/api/segment-category/export', async (req, res) => {
  try {
    const { whereString, params } = buildWhereClause(
      req.query,
      ['SegCatID', 'SegCatName', 'LastModifiedBy'], // Searchable fields
      ['SegCatID', 'SegCatName', 'LastModifiedBy', 'LastModifiedTs'] // Filterable columns
    );

    const dataQuery = `SELECT * FROM SegmentCategory ${whereString}`;
    const [results] = await db.query(dataQuery, params);

    if (results.length === 0) {
      return res.status(404).send("No data found to export for the given filters.");
    }

    const headers = Object.keys(results[0]);
    const csvHeader = headers.join(',');
    const csvRows = results.map(row =>
      headers.map(header => {
        const value = row[header];
        const strValue = String(value === null || value === undefined ? '' : value);
        return `"${strValue.replace(/"/g, '""')}"`;
      }).join(',')
    );
    const csvContent = [csvHeader, ...csvRows].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="segment_category_export.csv"');
    res.status(200).send(csvContent);
  } catch (err) {
    console.error("❌ Database query error on /api/segment-category/export:", err);
    res.status(500).json({ error: 'CSV export failed' });
  }
});

app.put('/api/segment-category/:SegCatID', async (req, res) => {
  const { SegCatID } = req.params;
  const { SegCatName, LastModifiedBy } = req.body;

  if (!SegCatID) {
    return res.status(400).json({ error: "SegCatID is required." });
  }
  if (!SegCatName) {
    return res.status(400).json({ error: "SegCatName is required." });
  }

  try {
    const query = `
      UPDATE SegmentCategory
      SET SegCatName = ?, LastModifiedBy = ?, LastModifiedTs = NOW()
      WHERE SegCatID = ?
    `;

    const [result] = await db.query(query, [SegCatName, LastModifiedBy || '', SegCatID]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: `Segment Category with ID ${SegCatID} not found.` });
    }

    res.status(200).json({ message: "Segment Category updated successfully." });
  } catch (err) {
    console.error("❌ Database query error on /api/segment-category/:SegCatID:", err);
    res.status(500).json({ error: "Failed to update Segment Category." });
  }
});

app.post('/api/segment-category', async (req, res) => {
  const { SegCatName, LastModifiedBy } = req.body;

  if (!SegCatName) {
    return res.status(400).json({ error: "SegCatName is required." });
  }

  try {
    const query = `
      INSERT INTO SegmentCategory (SegCatName, LastModifiedBy, LastModifiedTs)
      VALUES (?, ?, NOW())
    `;
    const [result] = await db.query(query, [SegCatName, LastModifiedBy || '']);

    res.status(201).json({
      message: "Segment Category added successfully.",
      SegCatID: result.insertId,
      SegCatName,
      LastModifiedBy: LastModifiedBy || '',
      LastModifiedTs: new Date().toISOString()
    });
  } catch (err) {
    console.error("❌ Database query error on POST /api/segment-category:", err);
    res.status(500).json({ error: "Failed to add Segment Category." });
  }
});

app.get('/api/is-audio-recorded/options', async (req, res) => {
  try {
    // 1. Fetch all non-empty, distinct IsAudioRecorded strings from the NewMediaLog table.
    const query = `
      SELECT DISTINCT IsAudioRecorded
      FROM NewMediaLog
      WHERE IsAudioRecorded IS NOT NULL AND TRIM(IsAudioRecorded) <> ''
    `;
    const [rows] = await db.query(query);

    // 2. Process the results to get individual unique values.
    const allValues = new Set();
    rows.forEach(row => {
      if (row.IsAudioRecorded) {
        row.IsAudioRecorded.split(',')
          .map(v => v.trim())
          .filter(v => v !== '')
          .forEach(v => allValues.add(v));
      }
    });

    // 3. Convert the Set to a sorted array of objects for the frontend.
    const uniqueValues = Array.from(allValues).sort();
    const results = uniqueValues.map(v => ({ IsAudioRecorded: v }));

    res.status(200).json(results);
  } catch (err) {
    console.error("❌ Database query error on /api/is-audio-recorded/options:", err);
    res.status(500).json({ error: 'Failed to fetch IsAudioRecorded options.' });
  }
});
// Start server
const PORT = process.env.PORT || 3600;
app.listen(PORT, () => {
 
  console.log(`🚀 Server running on port ${PORT}`);
});