import React from 'react';
import { CircularProgress, Paper } from "@mui/material";

const Loading = () => {
  return (
    <Paper className="loderBg">
      <div style={{ textAlign: "center", padding: "5px" }}>
        <CircularProgress />
        <div>Please wait for open source vulnerability scanning</div>
      </div>
    </Paper>
  );
};

export default Loading;
