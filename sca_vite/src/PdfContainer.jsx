import React from 'react';
import { Button } from "@mui/material";
import FileDownloadIcon from '@mui/icons-material/FileDownload';

export default (props) => {
  const bodyRef = React.createRef();
  const createPdf = () => props.createPdf(bodyRef.current);
  return (
    <section className="pdf-container">
      <section className="pdf-toolbar">
        {/* <button onClick={createPdf}>Download PDF</button> */}
        <Button variant="contained" onClick={createPdf} endIcon={<FileDownloadIcon />}>Download PDF</Button>
      </section>
      <section className="pdf-body" ref={bodyRef}>
        {props.children}
      </section>
    </section>
  )
}